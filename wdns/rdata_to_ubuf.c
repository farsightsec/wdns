static size_t
rdata_to_str_string_unquoted(const uint8_t *src, size_t len, ubuf *u)
{
	size_t n_bytes = 0;

	while (len--) {
		uint8_t c;

		c = *src++;
		if (c == '"') {
			ubuf_add_cstr(u, "\\\"");
		} else if (c == '\\') {
			ubuf_add_cstr(u, "\\\\");
		} else if (c >= ' ' && c <= '~') {
			ubuf_append(u, &c, 1);
		} else {
			ubuf_add_fmt(u, "\\%.3d", c);
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
		/* generic encoding */

		ubuf_add_cstr(u, "\\# ");
		ubuf_add_fmt(u, "%u ", rdlen);

		for (unsigned i = 0; i < rdlen; i++)
			ubuf_add_fmt(u, "%02x ", rdata[i]);

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
			ubuf_add_cstr(u, " ");
			bytes_consumed(len);
			break;

		case rdf_bytes:
			len = src_bytes;
			while (len > 0) {
				ubuf_add_fmt(u, "%02X", *src);
				src++;
				len--;
			}
			src_bytes = 0;
			break;

		case rdf_bytes_b64: {
			base64_encodestate b64;
			char *buf;
			base64_init_encodestate(&b64);
			buf = alloca(2 * src_bytes + 1);
			len = base64_encode_block((const char *) src, src_bytes, buf, &b64);
			ubuf_append(u, (uint8_t *) buf, len);
			len = base64_encode_blockend(buf, &b64);
			ubuf_append(u, (uint8_t *) buf, len);
			src_bytes = 0;
			break;
		}

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
				memcpy(addr, src, oclen);
				inet_ntop(AF_INET6, addr, pres, sizeof(pres));
				ubuf_add_cstr(u, pres);
				ubuf_add_cstr(u, " ");
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
				ubuf_add_cstr(u, "-");
			while (len > 0) {
				ubuf_add_fmt(u, "%02x", *src);
				src++;
				len--;
			}
			ubuf_add_cstr(u, " ");
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
				ubuf_add_cstr(u, "0 ");
				src_bytes --;
				break;
			}

			buf = alloca(2 * oclen + 1);
			len = base32_encode(buf, 2 * oclen + 1, src, oclen);
			ubuf_append(u, (uint8_t *) buf, len);
			ubuf_add_cstr(u, " ");
			src += oclen;
			src_bytes -= oclen + 1;
			break;
		}

		case rdf_int8: {
			uint8_t val;
			bytes_required(1);
			memcpy(&val, src, sizeof(val));
			ubuf_add_fmt(u, "%u ", val);
			bytes_consumed(1);
			break;
		}

		case rdf_int16: {
			uint16_t val;
			bytes_required(2);
			memcpy(&val, src, sizeof(val));
			val = ntohs(val);
			ubuf_add_fmt(u, "%hu ", val);
			bytes_consumed(2);
			break;
		}

		case rdf_int32: {
			uint32_t val;
			bytes_required(4);
			memcpy(&val, src, sizeof(val));
			val = ntohl(val);
			ubuf_add_fmt(u, "%u ", val);
			bytes_consumed(4);
			break;
		}

		case rdf_ipv4: {
			char pres[WDNS_PRESLEN_TYPE_A];
			bytes_required(4);
			inet_ntop(AF_INET, src, pres, sizeof(pres));
			ubuf_add_cstr(u, pres);
			ubuf_add_cstr(u, " ");
			bytes_consumed(4);
			break;
		}

		case rdf_ipv6: {
			char pres[WDNS_PRESLEN_TYPE_AAAA];
			bytes_required(16);
			inet_ntop(AF_INET6, src, pres, sizeof(pres));
			ubuf_add_cstr(u, pres);
			ubuf_add_cstr(u, " ");
			bytes_consumed(16);
			break;
		}

		case rdf_eui48: {
			bytes_required(6);
			for (size_t i = 0; i < 6; i++) {
				if (i != 0) {
					ubuf_add(u, '-');
				}
				ubuf_add_fmt(u, "%02x", src[i]);
			}
			bytes_consumed(6);
			break;
		}

		case rdf_eui64: {
			bytes_required(8);
			for (size_t i = 0; i < 8; i++) {
				if (i != 0) {
					ubuf_add(u, '-');
				}
				ubuf_add_fmt(u, "%02x", src[i]);
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
				ubuf_add_cstr(u, " ");
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
							my_rrtype = (window_block << 16) | lo;
							s_rrtype = wdns_rrtype_to_str(my_rrtype);
							if (s_rrtype != NULL) {
								ubuf_add_cstr(u, s_rrtype);
								ubuf_add_cstr(u, " ");
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
