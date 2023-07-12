/*
 * Copyright (c) 2023 DomainTools LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* IANA Address Family Numbers */
typedef enum {
	ip = 1,
	ip6 = 2,
} iana_addr_family_numbers;

/* EDNS0 Option Codes (OPT)*/
typedef enum {
	llq = 1,
	nsid = 3,
	dau = 5,
	dhu = 6,
	n3u = 7,
	edns_client_subnet = 8,
	edns_expire = 9,
	cookie = 10,
	edns_tcp_keepalive = 11,
	padding = 12,
	chain = 13,
	edns_key_tag = 14,
	extended_dns_error = 15,
	edns_client_tag = 16,
	edns_server_tag = 17,
	/* 18-20291 Unassigned */
	umbrella_ident = 20292,
	/* 20293-26945 Unassigned */
	deviceid = 26946,
	/* 26947-65000 Unassigned */
	/* 65001-65534 Reserved for Local/Experimental Use */
	reserved_for_future_expansion = 65535,
} edns0_option_codes;

/*
 * See RFC 8914 Section 5.2
 * [INFO-CODE] = "Purpose"
 */
const char * ede_purpose_array[] = {
	[0] = "Other Error",
	[1] = "Unsupported DNSKEY Algorithm",
	[2] = "Unsupported DS Digest Type",
	[3] = "Stale Answer",
	[4] = "Forged Answer",
	[5] = "DNSSEC Indeterminate",
	[6] = "DNSSEC Bogus",
	[7] = "Signature Expired",
	[8] = "Signature Not Yet Valid",
	[9] = "DNSKEY Missing",
	[10] = "RRSIGs Missing",
	[11] = "No Zone Key Bit Set",
	[12] = "NSEC Missing",
	[13] = "Cached Error",
	[14] = "Not Ready",
	[15] = "Blocked",
	[16] = "Censored",
	[17] = "Filtered",
	[18] = "Prohibited",
	[19] = "Stale NXDomain Answer",
	[20] = "Not Authoritative",
	[21] = "Not Supported",
	[22] = "No Reachable Authority",
	[23] = "Network Error",
	[24] = "Invalid Data",
	/* 25-49151 Unassigned */
	/* 49152-65535 Reserved for Private Use */
};

const size_t ede_purpose_array_len = sizeof(ede_purpose_array) / sizeof(char *);

static inline wdns_res
ip_to_ubuf(ubuf *u, uint16_t addr_family, const uint8_t *src, uint16_t src_bytes) {
	char pres[WDNS_PRESLEN_TYPE_AAAA];
	uint8_t addr[16] = {0};

	if (src_bytes == 0) {
		return (wdns_res_parse_error);
	} else if (addr_family != ip && addr_family != ip6) {
		return (wdns_res_parse_error);
	} else if (addr_family == ip && src_bytes > 4) {
		return (wdns_res_parse_error);
	} else if (addr_family == ip6 && src_bytes > 16) {
		return (wdns_res_parse_error);
	}

	memcpy(addr, src, src_bytes);
	fast_inet_ntop((addr_family == ip ? AF_INET : AF_INET6), addr, pres, sizeof(pres));
	ubuf_add_cstr(u, pres);
	return (wdns_res_success);
}

/*
 * Helper routine for adding EDNS0 Option Codes to a ubuf in the format of dig.
 */
void
_wdns_ednsoptcode_to_ubuf(ubuf *u, uint16_t option_code)
{
	ubuf_append_cstr_lit(u, "\n; ");
	switch (option_code) {
		case edns_client_subnet:
			ubuf_append_cstr_lit(u, "CLIENT-SUBNET:");
			break;
		case extended_dns_error:
			ubuf_append_cstr_lit(u, "EDE:");
			break;
		default:
			ubuf_add_fmt(u, "OPT=%u:", option_code);
			break;
	}
}

/*
 * Helper routine for adding EDNS0 Option Data to a ubuf in the format of dig.
 */
wdns_res
_wdns_ednsoptdata_to_ubuf(ubuf *u, uint16_t option_code, const uint8_t *src, uint16_t src_bytes)
{

#define bytes_required(n) do { \
	if (src_bytes < ((signed) (n))) \
		goto err; \
} while(0)

#define bytes_consumed(n) do { \
	src += n; \
	src_bytes -= n; \
} while(0)

#define print_printable(u, src, src_bytes) do { \
	for (uint16_t i = 0; i < src_bytes; i++) { \
		char c = isprint(src[i]) ? src[i] : '.'; \
		ubuf_add_fmt(u, "%c", c); \
	} \
} while(0)

	ubuf_add(u, ' ');
	switch (option_code) {
		case edns_client_subnet: {
			wdns_res res;
			uint16_t addr_family_num;
			uint8_t source_prefix_len, scope_prefix_len;

			/*
			 * RFC 7871. The first two octets in network byte order
			 * indicates the iana address family of the address
			 * contained in this option. The next two octets
			 * represent the Source Prefix-Length and Scope
			 * Prefix-Length respectively.
			 */
			bytes_required(sizeof(addr_family_num));
			memcpy(&addr_family_num, src, sizeof(addr_family_num));
			addr_family_num = ntohs(addr_family_num);
			bytes_consumed(sizeof(addr_family_num));

			bytes_required(sizeof(source_prefix_len));
			memcpy(&source_prefix_len, src, sizeof(source_prefix_len));
			bytes_consumed(sizeof(source_prefix_len));

			bytes_required(sizeof(scope_prefix_len));
			memcpy(&scope_prefix_len, src, sizeof(scope_prefix_len));
			bytes_consumed(sizeof(scope_prefix_len));

			/* Add the address to the ubuf in presentation format */
			res = ip_to_ubuf(u, addr_family_num, src, src_bytes);
			if (res != wdns_res_success) {
				goto err;
			}
			bytes_consumed(src_bytes);

			/*
			 * Finally, dig displays the source and scope prefix lens after
			 * the address.
			 */
			ubuf_add_fmt(u, "/%u/%u", source_prefix_len, scope_prefix_len);
			break;
		}
		case extended_dns_error: {
			char tmp[sizeof("65535")];
			const char *info_code_str;
			size_t len;
			uint16_t info_code;

			/*
			 * RFC 8914. The first two octets encoded in network
			 * byte order represents the INFO-CODE which is an
			 * index into the "Extended DNS Errors" registry.
			 */
			bytes_required(sizeof(info_code));
			memcpy(&info_code, src, sizeof(info_code));
			info_code = ntohs(info_code);
			bytes_consumed(sizeof(info_code));
			len = my_uint64_to_str(info_code, tmp, sizeof(tmp), &info_code_str);
			ubuf_append_cstr(u, info_code_str, len);

			/*
			 * Display the purpose string of info-codes that
			 * can be found in Section 5.2 of RFC 8914.
			 */
			if (info_code < ede_purpose_array_len) {
				ubuf_add_fmt(u, " (%s)", ede_purpose_array[info_code]);
			}

			/*
			 * Display the remaining octets enclosed without quotes
			 * in parentheses with printable octets printed and
			 * non-printable octets represented as dots.
			 */
			ubuf_append_cstr_lit(u, ": (");
			print_printable(u, src, src_bytes);
			ubuf_add(u, ')');
			break;
		}
		default:
			/*
			 * Default dig behavior of printing each octet's hex
			 * value separated by spaces.
			 */
			for (uint16_t i = 0; i < src_bytes; i++) {
				char tmp[sizeof("ff")];
				size_t tmp_len;
				tmp_len = my_bytes_to_hex_str(&src[i], 1, false, tmp, sizeof(tmp));
				ubuf_append_cstr(u, tmp, tmp_len);
				ubuf_add(u, ' ');
			}

			/*
			 * Followed by the same sequence repeated and enclosed
			 * in parentheses and quotes except now printable
			 * octets are printed and non-printable octets are
			 * represented as dots.
			 */
			ubuf_append_cstr_lit(u, "(\"");
			print_printable(u, src, src_bytes);
			ubuf_append_cstr_lit(u, "\")");
			break;
	}
	return (wdns_res_success);

err:
	return (wdns_res_parse_error);
#undef bytes_required
#undef bytes_consumed
#undef print_printable
}
