VECTOR_GENERATE(u16buf, uint16_t);

static size_t
rdata_to_str_string(const uint8_t *src, ubuf *u) {
	size_t len;
	uint8_t oclen;

	oclen = *src++;
	ubuf_add_cstr(u, "\"");

	len = oclen;
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
	}
	ubuf_add_cstr(u, "\" ");

	return (oclen + 1); /* number of bytes consumed from src */
}

static size_t
rdata_from_str_string(const uint8_t *src, ubuf *u) {
	const uint8_t *ptr = src;
	size_t u_orig_size = ubuf_size(u);
	bool is_quoted;

	if (*ptr == '"') {
		is_quoted = true;
		ptr++;
	} else {
		is_quoted = false;
	}

	while (*ptr) {
		if (is_quoted && *ptr == '"') {
			ptr++;
			return ptr-src;
		} else if ((!is_quoted) && isspace(*ptr)) {
			break;
		} else if (*ptr == '\\') {
			ptr++;
			if (*ptr == 0) {
				goto err;
			} else if (*ptr == '"' || *ptr == '\\') {
				ubuf_append(u, ptr++, 1);
			} else if (isdigit(*ptr)) {
				char dstr[4] = { 0, 0, 0, 0 };
				uint8_t c;
				uint16_t c_in;
				strncpy(dstr, (const char *)ptr, sizeof(dstr)-1);
				if (! (isdigit(dstr[1]) && isdigit(dstr[2]))) {
					goto err;
				}
				if (sscanf(dstr, "%hu", &c_in) == 0) {
					goto err;
				}
				c = (uint8_t) c_in;
				if (c != c_in) {
					goto err;
				}
				ubuf_append(u, &c, 1);
				ptr += 3;
			} else {
				goto err;
			}
		} else if (*ptr >= ' ' && *ptr <= '~') {
			ubuf_append(u, ptr++, 1);
		} else {
			goto err;
		}
	}

	if (!is_quoted) {
		return ptr-src;
	}

err:
	ubuf_clip(u, u_orig_size);
	return 0;
}

static int
cmp_u16(const void *a, const void *b) {
	uint16_t *u1 = (uint16_t *)a;
	uint16_t *u2 = (uint16_t *)b;
	return u1 == u2 ? 0 : u1 > u2 ? 1 : -1;
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

		case rdf_string: {
			bytes_required(1);
			oclen = *src;
			bytes_required(1 + oclen);
			len = rdata_to_str_string(src, u);
			bytes_consumed(len);
			break;
		}

		case rdf_repstring:
			while (src_bytes > 0) {
				bytes_required(1);
				oclen = *src;
				bytes_required(1 + oclen);
				len = rdata_to_str_string(src, u);
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

wdns_res
_wdns_str_to_rdata_ubuf(ubuf *u, const char * str,
			uint16_t rrtype, uint16_t rrclass) {
	wdns_res res;
	const record_descr *descr = NULL;
	size_t u_orig_size = ubuf_size(u);

	if (rrtype < record_descr_len)
		descr = &record_descr_array[rrtype];

	if (rrtype >= record_descr_len ||
	    (descr != NULL && descr->types[0] == rdf_unknown))
	{
		/* generic encoding */

		if (strncmp(str, "\\#", 2)) {
			res = wdns_res_parse_error;
			goto err;
		}
		str += 2;
		if (!isspace(str)) {
			res = wdns_res_parse_error;
			goto err;
		}
		while (isspace(*++str));

		while (*str) {
			uint8_t c;
			if (*(str+1) == 0) {
				res = wdns_res_parse_error;
				goto err;
			}
			if (!sscanf(str, "%02hhx", &c)) {
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_append(u, &c, 1);
			str += 2;
		}

		return (wdns_res_success);
	} else if (descr != NULL && !(descr->record_class == class_un ||
				      descr->record_class == rrclass))
	{
		return (wdns_res_success);
	}

	for (const uint8_t *t = &descr->types[0]; *t != rdf_end; t++) {
		if (str == NULL) {
			break;
		}

		while (isspace(*str)) {
			str++;
		}

		if (*str == 0) {
			break;
		}

		switch (*t) {
		case rdf_name:
		case rdf_uname: {
			wdns_name_t *name;
			char * s;
			const char *end = strpbrk(str, " \t\r\n");

			if (end != NULL) {
				s = strndup(str, end-str);
			} else {
				s = strdup(str);
			}
			name = calloc(1, sizeof(*name));

			res = wdns_str_to_name(s, name);
			if (res != wdns_res_success) {
				free(s);
				free(name);
				goto err;
			}

			ubuf_append(u, name->data, name->len);
			str = end;

			free(s);
			if(name->data) {
				free (name->data);
			}
			free(name);

			break;
		}

		case rdf_bytes:
			while (*str) {
				uint8_t c;
				if (*(str+1) == 0) {
					res = wdns_res_parse_error;
					goto err;
				}
				if (!sscanf(str, "%02hhx", &c)) {
					res = wdns_res_parse_error;
					goto err;
				}
				ubuf_append(u, &c, 1);
				str += 2;
			}
			break;

		case rdf_bytes_b64: {
			base64_decodestate b64;
			char *buf;
			size_t str_len = strlen(str);
			size_t buf_len;

			base64_init_decodestate(&b64);
			buf = alloca((str_len+1) / 2 + 1);
			buf_len = base64_decode_block((const char *) str, str_len, buf, &b64);
			ubuf_append(u, (uint8_t *) buf, buf_len);
			str += str_len;
			break;
		}

		case rdf_ipv6prefix: {
			uint8_t prefix_len;
			const char *end = strpbrk(str, " \t\r\n");
			const char *ptr = str;

			if (end == NULL) {
				end = str + strlen(str);
			}

			while (ptr < end) {
				if (!isdigit(*ptr++)) {
					res = wdns_res_parse_error;
					goto err;
				}
			}

			if (sscanf(str, "%hhu", &prefix_len) == 0) {
				res = wdns_res_parse_error;
				goto err;
			}

			if (prefix_len > 128) {
				res = wdns_res_parse_error;
				goto err;
			}

			ubuf_append(u, &prefix_len, sizeof(prefix_len));

			str = end;
			if (str) {
				while (isspace(*str)) {
					str++;
				}
			}

			if (prefix_len > 0) {
				if (str == NULL || *str == 0) {
					res = wdns_res_parse_error;
					goto err;
				}

				end = strpbrk(str, " \t\r\n");

				uint8_t oclen = prefix_len / 8;
				if (prefix_len % 8 > 0) {
					oclen++;
				}

				uint8_t addr[16];
				char * pres;

				if (end != NULL) {
					pres = strndup(str, end-str);
				} else {
					pres = strdup(str);
				}

				int pton_res = inet_pton(AF_INET6, pres, addr);
				free(pres);

				if (pton_res == 1) {
					ubuf_append(u, addr, oclen);
				} else {
					res = wdns_res_parse_error;
					goto err;
				}

				str = end;
			}

			break;
		}

		case rdf_salt: {
			const char *end = strpbrk(str, " \t\r\n");
			if (end == NULL) {
				end = str + strlen(str);
			}

			if (*str == '-' && (end-str) == 1) {
				uint8_t c = 0;
				ubuf_append(u, &c, 1);
				str++;
			} else {
				if (end-str > (2*UINT8_MAX) || (end-str) % 2 == 1) {
					res = wdns_res_parse_error;
					goto err;
				}
				uint8_t oclen = (uint8_t)(end-str)/2;
				ubuf_append(u, &oclen, 1);

				while (oclen > 0) {
					uint8_t c;
					if (!sscanf(str, "%02hhx", &c)) {
						res = wdns_res_parse_error;
						goto err;
					}
					ubuf_append(u, &c, 1);
					str += 2;
					oclen--;
				}
			}
			break;
		}

		case rdf_hash: {
			char *buf;
			size_t buf_len;
			const char *end = strpbrk(str, " \t\r\n");

			if (end == NULL) {
				end = str + strlen(str);
			}

			size_t str_len = end-str;
			buf = malloc(str_len);
			buf_len = base32_decode(buf, str_len, str, str_len);

			uint8_t oclen = (uint8_t)buf_len;
			if (oclen != buf_len) {
				free(buf);
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_append(u, &oclen, 1);
			ubuf_append(u, (uint8_t *) buf, oclen);
			free(buf);
			str = end;
			break;
		}

		case rdf_int8: {
			uint64_t s_val;
			uint8_t val;
			const char *ptr = str;
			const char *end = strpbrk(str, " \t\r\n");

			if (end == NULL) {
				end = str + strlen(str);
			}

			while (ptr < end) {
				if (!isdigit(*ptr++)) {
					res = wdns_res_parse_error;
					goto err;
				}
			}

			if (sscanf(str, "%" PRIu64, &s_val)) {
				val = (uint8_t)s_val;
				if (val != s_val) {
					res = wdns_res_parse_error;
					goto err;
				}
				ubuf_append(u, &val, sizeof(val));
			}
			str = end;
			break;
		}

		case rdf_int16: {
			uint64_t s_val;
			uint16_t val;
			const char *ptr = str;
			const char *end = strpbrk(str, " \t\r\n");

			if (end == NULL) {
				end = str + strlen(str);
			}

			while (ptr < end) {
				if (!isdigit(*ptr++)) {
					res = wdns_res_parse_error;
					goto err;
				}
			}

			if (sscanf(str, "%" PRIu64, &s_val)) {
				val = (uint16_t)s_val;
				if (val != s_val) {
					res = wdns_res_parse_error;
					goto err;
				}
				val = htons(val);
				ubuf_append(u, (uint8_t*)&val, sizeof(val));
			}
			str = end;
			break;
		}

		case rdf_int32: {
			uint64_t s_val;
			uint32_t val;
			const char *ptr = str;
			const char *end = strpbrk(str, " \t\r\n");

			if (end == NULL) {
				end = str + strlen(str);
			}

			while (ptr < end) {
				if (!isdigit(*ptr++)) {
					res = wdns_res_parse_error;
					goto err;
				}
			}

			if (sscanf(str, "%" PRIu64, &s_val)) {
				val = (uint32_t)s_val;
				if (val != s_val) {
					res = wdns_res_parse_error;
					goto err;
				}
				val = htonl(val);
				ubuf_append(u, (uint8_t*)&val, sizeof(val));
			}
			str = end;
			break;
		}

		case rdf_ipv4: {
			uint8_t addr[4];
			char * pres;
			int pton_res;
			const char *end = strpbrk(str, " \t\r\n");

			if (end == NULL) {
				end = str + strlen(str);
			}

			pres = strdup(str);
			pres[end-str] = 0;
			pton_res = inet_pton(AF_INET, pres, addr);
			free(pres);

			if (pton_res == 1) {
				ubuf_append(u, addr, sizeof(addr));
			} else {
				res = wdns_res_parse_error;
				goto err;
			}

			str = end;
			break;
		}

		case rdf_ipv6: {
			uint8_t addr[16];
			char * pres;
			int pton_res;
			const char *end = strpbrk(str, " \t\r\n");

			if (end != NULL) {
				pres = strndup(str, end-str);
			} else {
				pres = strdup(str);
			}
			pton_res = inet_pton(AF_INET6, pres, addr);
			free(pres);

			if (pton_res == 1) {
				ubuf_append(u, addr, sizeof(addr));
			} else {
				res = wdns_res_parse_error;
				goto err;
			}

			str = end;
			break;
		}

		case rdf_string: {
			const char * end = str;
			size_t u_oclen_offset;
			size_t str_len;
			uint8_t oclen = 0;

			u_oclen_offset = ubuf_size(u);
			ubuf_append(u, &oclen, sizeof(oclen));

			end += rdata_from_str_string((const uint8_t*)str, u);
			if (end == str) {
				res = wdns_res_parse_error;
				goto err;
			}
			str_len = ubuf_size(u) - u_oclen_offset - 1;

			oclen = (uint8_t)str_len;
			if (oclen != str_len) {
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_data(u)[u_oclen_offset] = oclen;

			str = end;
			break;
		}

		case rdf_repstring: {
			const char * end;
			size_t u_oclen_offset;
			size_t str_len;
			uint8_t oclen = 0;

			while (*str) {
				if (isspace(*str)) {
					str++;
					continue;
				}

				end = str;
				oclen = 0;

				u_oclen_offset = ubuf_size(u);
				ubuf_append(u, &oclen, sizeof(oclen));

				end += rdata_from_str_string((const uint8_t*)str, u);
				if (end == str) {
					res = wdns_res_parse_error;
					goto err;
				}
				str_len = ubuf_size(u) - u_oclen_offset - 1;

				oclen = (uint8_t)str_len;
				if (oclen != str_len) {
					res = wdns_res_parse_error;
					goto err;
				}
				ubuf_data(u)[u_oclen_offset] = oclen;

				str = end;
			}

			break;
		}

		case rdf_rrtype: {
			char * s_rrtype;
			uint16_t my_rrtype;
			const char *end = strpbrk(str, " \t\r\n");

			if (end != NULL) {
				s_rrtype = strndup(str, end-str);
			} else {
				s_rrtype = strdup(str);
			}
			my_rrtype = htons(wdns_str_to_rrtype(s_rrtype));
			free(s_rrtype);

			if (my_rrtype > 0) {
				ubuf_append(u, (const uint8_t*)&my_rrtype, sizeof(my_rrtype));
			} else {
				res = wdns_res_parse_error;
				goto err;
			}

			str = end;
			break;
		}

		case rdf_type_bitmap: {
			const char *end;
			char *s_rrtype;
			u16buf *rrtypes;
			uint16_t my_rrtype, last_rrtype;
			size_t n;
			uint8_t window_block, bitmap_len;
			uint8_t bitmap[32];

			rrtypes = u16buf_init(16);
			if (! rrtypes) {
				res = wdns_res_malloc;
				goto err;
			}

			while (str != NULL && *str) {
				if (isspace(*str)) {
					str++;
					continue;
				}

				end = strpbrk(str, " \t\r\n");
				if (end != NULL) {
					s_rrtype = strndup(str, end-str);
				} else {
					s_rrtype = strdup(str);
				}

				my_rrtype = wdns_str_to_rrtype(s_rrtype);
				free(s_rrtype);

				if (my_rrtype == 0 || (rrtype >= 128 && rrtype < 256) || rrtype == 65535) {
					res = wdns_res_parse_error;
					goto err;
				}

				u16buf_add(rrtypes, my_rrtype);
				str = end;
			}
			qsort(u16buf_ptr(rrtypes), u16buf_size(rrtypes), sizeof(uint16_t), cmp_u16);

			memset(bitmap, 0, sizeof(bitmap));
			window_block = 0;
			bitmap_len = 0;
			last_rrtype = 0;

			for (n = 0; n < u16buf_size(rrtypes); n++) {
				my_rrtype = u16buf_value(rrtypes, n);
				if (my_rrtype == last_rrtype) {
					continue;
				}
				last_rrtype = my_rrtype;

				uint8_t cur_window = my_rrtype / 256;

				if (cur_window != window_block) {
					ubuf_append(u, (const uint8_t*)&window_block, sizeof(window_block));
					ubuf_append(u, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
					ubuf_append(u, (const uint8_t*)bitmap, bitmap_len);
					memset(bitmap, 0, sizeof(bitmap));
					window_block = cur_window;
				}

				uint8_t offset = my_rrtype % 256;
				uint8_t byte = offset / 8;
				uint8_t bit = offset % 8;

				bitmap[byte] |= 0x80 >> bit;
				bitmap_len = 1 + byte;
			}
			ubuf_append(u, (const uint8_t*)&window_block, sizeof(window_block));
			ubuf_append(u, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
			ubuf_append(u, (const uint8_t*)bitmap, bitmap_len);

			u16buf_destroy(&rrtypes);
			break;
		}
		default: {
			res = wdns_res_failure;
			goto err;
		}
		} /* switch */
	}

	return wdns_res_success;

err:
	ubuf_clip(u, u_orig_size);
	return res;
}
