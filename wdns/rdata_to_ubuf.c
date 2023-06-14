/*
 * Copyright (c) 2022 DomainTools LLC
 * Copyright (c) 2012-2017, 2021 by Farsight Security, Inc.
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

#include <arpa/inet.h>

static size_t
rdata_to_str_string_unquoted(const uint8_t *src, size_t len, ubuf *u)
{
	size_t n_bytes = 0;

	while (len--) {
		uint8_t c;

		c = *src++;
		if (c == '"') {
			ubuf_add_cstr_lit(u, "\\\"");
		} else if (c == '\\') {
			ubuf_add_cstr_lit(u, "\\\\");
		} else if (c >= ' ' && c <= '~') {
			ubuf_append(u, &c, 1);
		} else {
			char tmp[4];
			ubuf_add(u, '\\');
			ubuf_append_cstr(u, my_uint64_to_str_padded(c, 3, tmp), 3);
		}
		n_bytes += 1;
	}

	return n_bytes; /* number of bytes consumed from src */
}

static size_t
rdata_to_str_string(const uint8_t *src, size_t len, ubuf *u)
{
	ubuf_add(u, '"');
	size_t n_bytes = rdata_to_str_string_unquoted(src, len, u);
	ubuf_add(u, '"');

	/* Will be truncated later, if unused. */
	ubuf_add(u, ' ');

	return n_bytes;
}

/*
 * bytes_to_ubuf_base64() encodes a base64 string and appends it to the
 * given ubuf.
 */
static void
bytes_to_ubuf_base64(uint8_t *src, uint16_t src_len, ubuf *u)
{
	char *buf;
	size_t len;
	base64_encodestate b64;

	base64_init_encodestate(&b64);
	buf = malloc(2 * src_len + 1);

	len = base64_encode_block((const char *)src, src_len, buf, &b64);
	ubuf_append(u, (uint8_t *)buf, len);

	len = base64_encode_blockend(buf, &b64);
	ubuf_append(u, (uint8_t *)buf, len);

	free(buf);
}

/*
 * svcparam_to_str() converts a wire format SvcParamVal to a string.
 *
 * See str_to_svcparam() for the opposite functionality.
 */
static wdns_res
svcparam_to_str(uint16_t key, const uint8_t *src, uint16_t len, ubuf *u)
{
	uint8_t *ptr = (uint8_t *)src;
	uint16_t val;
	uint8_t oclen;

	assert(key != spr_invalid);
	assert(u != NULL);

	switch (key) {
	case spr_mandatory:
		while ((ptr - src) < len) {
			char key_str[16] = { 0 };

			if ((ptr + sizeof(val) - src) > len) {
				return (wdns_res_parse_error);
			}

			(void) memcpy(&val, ptr, sizeof(val));
			ptr += sizeof(val);

			val = ntohs(val);

			if (_wdns_svcparamkey_to_str(val, key_str,
			    sizeof(key_str)) != NULL) {
				ubuf_add_fmt(u, "%s", key_str);
			}

			if ((ptr - src) < len) {
				ubuf_add(u, ',');
			} else {
				ubuf_add(u, ' ');
			}
		}
		break;

	case spr_nd_alpn:
		/*
		 * For "no-default-alpn", the presentation and wire format
		 * values MUST be empty. When "no-default-alpn" is specified in
		 * an RR, "alpn" must also be specified in order for the RR to
		 * be "self-consistent".
		 */
		if (len != 0) {
			return (wdns_res_parse_error);
		}
		ubuf_add(u, ' ');
		break;

	case spr_port: {
		char tmp[10];
		size_t tmp_len;
		/*
		 * The wire format of the SvcParamValue is the corresponding 2
		 * octet numeric value in network byte order.
		 */
		if (len != 2) {
			return (wdns_res_parse_error);
		}
		(void) memcpy(&val, ptr, sizeof(val));
		val = ntohs(val);
		tmp_len = my_uint64_to_str(val, tmp);
		ubuf_append_cstr(u, tmp, tmp_len);
		ubuf_add(u, ' ');
	}
		break;

	case spr_ech:
		/*
		 * In wire format, the value of the parameter is an
		 * ECHConfigList [ECH], including the redundant length prefix.
		 */
		bytes_to_ubuf_base64(ptr, len, u);
		ubuf_add(u, ' ');
		break;

	/*
	 * The wire format for IP hints is a sequence of IP addresses in
	 * network byte order. An empty list of addresses is invalid.
	 */
	case spr_ipv4hint:
		while ((ptr - src) < len) {
			char pres[INET_ADDRSTRLEN] = { 0 };

			if (ptr + 4 > src + len) {
				return (wdns_res_parse_error);
			}

			if (inet_ntop(AF_INET, ptr, pres,
			    sizeof(pres)) == NULL) {
				return (wdns_res_parse_error);
			}

			ubuf_add_cstr(u, pres);
			ptr += 4;

			if ((ptr - src) < len) {
				ubuf_add(u, ',');
			} else {
				ubuf_add(u, ' ');
			}
		}
		break;

	case spr_ipv6hint:
		while ((ptr - src) < len) {
			char pres[INET6_ADDRSTRLEN] = { 0 };

			if (ptr + 16 > src + len) {
				return (wdns_res_parse_error);
			}

			if (inet_ntop(AF_INET6, ptr, pres,
			    sizeof(pres)) == NULL) {
				return (wdns_res_parse_error);
			}

			ubuf_add_cstr(u, pres);
			ptr += 16;

			if ((ptr - src) < len) {
				ubuf_add(u, ',');
			} else {
				ubuf_add(u, ' ');
			}
		}
		break;

	/*
	 * The wire format value for "alpn" consists of at least one * "alpn-id"
	 * prefixed by its length as a single octet, and these length-value
	 * pairs are concatenated to form the SvcParamValue. These MUST exactly
	 * fill the SvcParamValue; otherwise, the SvcParamValue is malformed.
	 *
	 * Note that we always wrap such values around double quotes in
	 * presentation format.
	 */
	case spr_alpn:
		ubuf_add(u, '"');

		while ((ptr - src) < len) {
			uint8_t l;

			oclen = *ptr;
			ptr += 1;       /* skip the length */

			if ((ptr + oclen - src) > len) {
				return (wdns_res_parse_error);
			}

			l = oclen;

			while (l--) {
				/*
				 * Presentation format is encoded as a
				 * character string, which then needs to be
				 * represented as a C character string. This
				 * makes backslash escaping a bit tricky.
				 *
				 * Here's an example case:
				 *  (a) wire format "f\oo,bar"
				 *  (b) represented as "f\\oo\,bar"
				 *  (c) presentation format "f\\\\oo\\,bar"
				 *
				 * Furthermore, these escape sequences are
				 * expressed as C string literals below,
				 * requiring another round of escaping for the
				 * backslashes.
				 */
				uint8_t c = *ptr++;

				if (c == '"') {
					ubuf_add_cstr_lit(u, "\\\"");
				} else if (c == '\\') {
					ubuf_add_cstr_lit(u, "\\\\\\\\");
				} else if (c == ',') {
					ubuf_add_cstr_lit(u, "\\\\,");
				} else if (c >= ' ' && c <= '~') {
					ubuf_append(u, &c, 1);
				} else {
					char tmp[4];
					ubuf_add(u, '\\');
					ubuf_append_cstr(u, my_uint64_to_str_padded(c, 3, tmp), 3);
				}
			}

			if ((ptr - src) < len) {
				ubuf_add(u, ',');
			} else {
				ubuf_add(u, '"');
			}
		}
		ubuf_add(u, ' ');
		break;

	default:
		rdata_to_str_string(ptr, len, u);
		break;
	}

	return (wdns_res_success);
}

void
_wdns_rdata_to_ubuf(ubuf *u, const uint8_t *rdata, uint16_t rdlen,
		    uint16_t rrtype, uint16_t rrclass)
{

#define bytes_required(n) do { \
	if (src_bytes < ((signed) (n))) \
		goto err; \
} while(0)

#define bytes_consumed(n) do { \
	src += n; \
	src_bytes -= n; \
} while(0)

	char domain_name[WDNS_PRESLEN_NAME];
	const record_descr *descr = NULL;
	const uint8_t *src;
	size_t len;
	ssize_t src_bytes;
	uint8_t oclen;
	wdns_res res;

	if (rrtype < record_descr_len)
		descr = &record_descr_array[rrtype];

	if (rrtype >= record_descr_len ||
	    (descr != NULL && descr->types[0] == rdf_unknown))
	{
		char tmp[10];
		/* generic encoding */

		ubuf_add_cstr_lit(u, "\\# ");
		len = my_uint64_to_str(rdlen, tmp);
		ubuf_append_cstr(u, tmp, len);
		ubuf_add(u, ' ');

		for (unsigned i = 0; i < rdlen; i++)
			ubuf_append_cstr(u, my_uint8_to_hex_str_padded(rdata[i],tmp),2);

		return;

	} else if (descr != NULL && !(descr->record_class == class_un ||
				      descr->record_class == rrclass))
	{
		return;
	}

	src = rdata;
	src_bytes = (ssize_t) rdlen;

	for (const uint8_t *t = &descr->types[0]; *t != rdf_end; t++) {
		if (src_bytes == 0)
			break;

		switch (*t) {
		case rdf_name:
		case rdf_uname:
			res = wdns_len_uname(src, src + src_bytes, &len);
			if (res != wdns_res_success)
				goto err_res;
			wdns_domain_to_str(src, len, domain_name);
			ubuf_add_cstr(u, domain_name);
			ubuf_add(u, ' ');
			bytes_consumed(len);
			break;

		case rdf_bytes:
			len = src_bytes;
			while (len > 0) {
				char tmp[3];
				ubuf_append_cstr(u, my_uint8_to_hex_STR_padded(*src, tmp), 2);
				src++;
				len--;
			}
			src_bytes = 0;
			break;

		case rdf_bytes_b64:
			bytes_to_ubuf_base64((uint8_t *)src, src_bytes, u);
			src_bytes = 0;
			break;

		case rdf_bytes_str:
			len = rdata_to_str_string(src, src_bytes, u);
			bytes_consumed(len);
			break;

		case rdf_ipv6prefix: {
			uint8_t prefix_len;
			uint8_t addr[16];
			char pres[WDNS_PRESLEN_TYPE_AAAA];

			bytes_required(1);
			prefix_len = *src++;

			if (prefix_len > 128) {
				goto err;
			}

			oclen = (128-prefix_len) / 8;
			if (prefix_len % 8 != 0) {
				oclen++;
			}
			bytes_required(1 + oclen);

			ubuf_add_fmt(u, "%d ", prefix_len);

			if (oclen > 0) {
				memset(addr, 0, sizeof(addr));
				memcpy(addr + sizeof(addr) - oclen, src, oclen);
				inet_ntop(AF_INET6, addr, pres, sizeof(pres));
				ubuf_add_cstr(u, pres);
				ubuf_add(u, ' ');
			}
			src_bytes -= oclen + 1;
			src += oclen;
			break;
		}

		case rdf_salt:
			bytes_required(1);
			len = oclen = *src++;
			bytes_required(1 + oclen);
			if (oclen == 0)
				ubuf_add_cstr_lit(u, "-");
			while (len > 0) {
				char tmp[3];
				ubuf_append_cstr(u, my_uint8_to_hex_str_padded(*src, tmp), 2);
				src++;
				len--;
			}
			ubuf_add(u, ' ');
			src_bytes -= oclen + 1;
			break;

		case rdf_hash: {
			char *buf;
			bytes_required(1);
			oclen = *src++;
			bytes_required(1 + oclen);
			/*
			 * RFC 5155 provides a "-" notation for salt with length zero,
			 * but no similar notation for hash with length zero. We use a
			 * single "0" character in this case to preserve the presentation
			 * syntax requirement of a sequence of base32 digits, while not
			 * conflicting with the base32 encoding of any one (or more) byte
			 * sequences.
			 */
			if (oclen == 0) {
				ubuf_add_cstr_lit(u, "0 ");
				src_bytes --;
				break;
			}

			buf = alloca(2 * oclen + 1);
			len = base32_encode(buf, 2 * oclen + 1, src, oclen);
			ubuf_append(u, (uint8_t *) buf, len);
			ubuf_add(u, ' ');
			src += oclen;
			src_bytes -= oclen + 1;
			break;
		}

		case rdf_int8: {
			char tmp[10];
			size_t tmp_len;
			uint8_t val;
			bytes_required(1);
			memcpy(&val, src, sizeof(val));
			tmp_len = my_uint64_to_str(val, tmp);
			ubuf_append_cstr(u, tmp, tmp_len);
			ubuf_add(u, ' ');
			bytes_consumed(1);
			break;
		}

		case rdf_int16: {
			char tmp[10];
			size_t tmp_len;
			uint16_t val;
			bytes_required(2);
			memcpy(&val, src, sizeof(val));
			val = ntohs(val);
			tmp_len = my_uint64_to_str(val, tmp);
			ubuf_append_cstr(u, tmp, tmp_len);
			ubuf_add(u, ' ');
			bytes_consumed(2);
			break;
		}

		case rdf_int32: {
			char tmp[15];
			size_t tmp_len;
			uint32_t val;
			bytes_required(4);
			memcpy(&val, src, sizeof(val));
			val = ntohl(val);
			tmp_len = my_uint64_to_str(val, tmp);
			ubuf_append_cstr(u, tmp, tmp_len);
			ubuf_add(u, ' ');
			bytes_consumed(4);
			break;
		}

		case rdf_ipv4: {
			char pres[WDNS_PRESLEN_TYPE_A];
			bytes_required(4);
			inet_ntop(AF_INET, src, pres, sizeof(pres));
			ubuf_add_cstr(u, pres);
			ubuf_add(u, ' ');
			bytes_consumed(4);
			break;
		}

		case rdf_ipv6: {
			char pres[WDNS_PRESLEN_TYPE_AAAA];
			bytes_required(16);
			inet_ntop(AF_INET6, src, pres, sizeof(pres));
			ubuf_add_cstr(u, pres);
			ubuf_add(u, ' ');
			bytes_consumed(16);
			break;
		}

		case rdf_eui48: {
			bytes_required(6);
			for (size_t i = 0; i < 6; i++) {
				char tmp[3];
				if (i != 0) {
					ubuf_add(u, '-');
				}
				ubuf_append_cstr(u, my_uint8_to_hex_str_padded(src[i], tmp), 2);
			}
			bytes_consumed(6);
			break;
		}

		case rdf_eui64: {
			bytes_required(8);
			for (size_t i = 0; i < 8; i++) {
				char tmp[3];
				if (i != 0) {
					ubuf_add(u, '-');
				}
				ubuf_append_cstr(u, my_uint8_to_hex_str_padded(src[i], tmp), 2);
			}
			bytes_consumed(8);
			break;
		}

		case rdf_string: {
			bytes_required(1);
			oclen = *src;
			bytes_consumed(1);

			bytes_required(oclen);
			len = rdata_to_str_string(src, oclen, u);
			bytes_consumed(len);
			break;
		}

		case rdf_svcparams: {
			/*
			 * Wire format for the SvcParams portion of a
			 * SVCB or HTTPS message, parsed per section
			 * 2.2 of draft-ietf-dnsop-svcb-https-08.
			 */
			uint16_t key, val_len;

			while (src_bytes > 0) {
				char key_str[16] = { 0 };

				/*
				 * A 2 octet field containing the SvcParamKey
				 * in network byte order.
				 */
				bytes_required(2);
				(void) memcpy(&key, src, sizeof(key));
				key = ntohs(key);

				if (_wdns_svcparamkey_to_str(key, key_str,
				    sizeof(key_str)) == NULL) {
					goto err;
				}

				if (key == spr_invalid) {
					goto err;
				}

				/* no-default-alpn has no value */
				if (key != spr_nd_alpn) {
					ubuf_add_fmt(u, "%s=", key_str);
				} else {
					ubuf_add_fmt(u, "%s", key_str);
				}

				bytes_consumed(2);

				/*
				 * A 2 octet field containing the length of
				 * the SvcParamValue also in network byte order.
				 */
				bytes_required(2);
				(void) memcpy(&val_len, src, sizeof(val_len));
				val_len = ntohs(val_len);
				bytes_consumed(2);

				/*
				 * An octet string of 'val_len' length whose
				 * contents are in a format determined by the
				 * key specified in 'key'.
				 */
				bytes_required(val_len);

				res = svcparam_to_str(key, src, val_len, u);
				if (res != wdns_res_success) {
					goto err_res;
				}

				bytes_consumed(val_len);
			}
			break;
		}

		case rdf_repstring:
			while (src_bytes > 0) {
				bytes_required(1);
				oclen = *src;
				bytes_consumed(1);

				bytes_required(oclen);
				len = rdata_to_str_string(src, oclen, u);
				bytes_consumed(len);
			}
			break;

		case rdf_rrtype: {
			const char *s_rrtype;
			uint16_t my_rrtype;

			bytes_required(2);
			memcpy(&my_rrtype, src, 2);
			my_rrtype = ntohs(my_rrtype);
			bytes_consumed(2);

			s_rrtype = wdns_rrtype_to_str(my_rrtype);
			if (s_rrtype != NULL) {
				ubuf_add_cstr(u, s_rrtype);
				ubuf_add(u, ' ');
			} else {
				ubuf_add_fmt(u, "TYPE%hu ", my_rrtype);
			}

			break;
		}

		case rdf_type_bitmap: {
			const char *s_rrtype;
			uint16_t my_rrtype, lo;
			uint8_t a, b, window_block, bitmap_len;

			bytes_required(2);
			while (src_bytes >= 2) {
				window_block = *src;
				bitmap_len = *(src + 1);
				bytes_consumed(2);
				bytes_required(bitmap_len);
				lo = 0;
				for (int i = 0; i < bitmap_len; i++) {
					a = src[i];
					for (int j = 1; j <= 8; j++) {
						b = a & (1 << (8 - j));
						if (b != 0) {
							my_rrtype = (window_block << 8) | lo;
							s_rrtype = wdns_rrtype_to_str(my_rrtype);
							if (s_rrtype != NULL) {
								ubuf_add_cstr(u, s_rrtype);
								ubuf_add(u, ' ');
							} else {
								ubuf_add_fmt(u, "TYPE%hu ", my_rrtype);
							}
						}
						lo += 1;
					}
				}
				bytes_consumed(bitmap_len);
			}
			break;
		}

		case rdf_edns_opt_rdata: {
			uint16_t option_code, option_len;

			while (src_bytes > 0) {
				/*
				 * A 2 octet field containing the option code in
				 * network byte order. See RFC 6891 Section 6.1.2.
				 */
				bytes_required(2);
				memcpy(&option_code, src, sizeof(option_code));
				option_code = ntohs(option_code);
				_wdns_ednsoptcode_to_ubuf(u, option_code);
				bytes_consumed(2);

				/*
				 * A 2 octet field containing the length of the
				 * option data in network byte order.
				 */
				bytes_required(2);
				memcpy(&option_len, src, sizeof(option_len));
				option_len = ntohs(option_len);
				bytes_consumed(2);

				bytes_required(option_len);
				res = _wdns_ednsoptdata_to_ubuf(u, option_code,
					src, option_len);
				if (res != wdns_res_success) {
					goto err_res;
				}
				bytes_consumed(option_len);
			}
			break;
		} /* end case */

		}
	}

	/* truncate trailing " " */
	if (ubuf_size(u) > 0 && ubuf_value(u, ubuf_size(u) - 1) == ' ')
		ubuf_clip(u, ubuf_size(u) - 1);

	return;

err:
	ubuf_add_fmt(u, " ### PARSE ERROR ###");
	return;

err_res:
	ubuf_add_fmt(u, " ### PARSE ERROR #%u ###", res);
	return;
}
