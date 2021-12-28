/*
 * Copyright (c) 2015-2018, 2021 by Farsight Security, Inc.
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

VECTOR_GENERATE(u16buf, uint16_t)

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

/*
 * base64_str_to_ubuf() decodes a base64 value and appends it to the given ubuf.
 */
static size_t
base64_str_to_ubuf(const char *str, size_t str_len, ubuf *u)
{
	base64_decodestate b64;
	char *buf;
	size_t buf_len;

	base64_init_decodestate(&b64);
	buf = malloc(str_len+1);
	buf_len = base64_decode_block((const char *) str, str_len, buf, &b64);
	ubuf_append(u, (uint8_t *) buf, buf_len);
	free(buf);

	return (buf_len);
}

/*
 * str_to_ubuf() appends a string to a ubuf, prepending its length first.
 */
static wdns_res
str_to_ubuf(const char *str, ubuf *u, const char **retp)
{
	const char *end = str;
	size_t u_oclen_offset;
	size_t str_len;
	uint8_t oclen = 0;

	u_oclen_offset = ubuf_size(u);
	ubuf_append(u, &oclen, sizeof(oclen));

	end += rdata_from_str_string((const uint8_t*)str, u);
	if (end == str) {
	        return (wdns_res_parse_error);
	}
	str_len = ubuf_size(u) - u_oclen_offset - 1;

	oclen = (uint8_t)str_len;
	if (oclen != str_len) {
	        return (wdns_res_parse_error);
	}
	ubuf_data(u)[u_oclen_offset] = oclen;

	if (retp != NULL) {
		*retp = end;
	}

	return (wdns_res_success);
}

/*
 * str_to_svcparam() translates a "key=val" string to the SVCB/HTTPS wire
 * format as specified in draft-ietf-dnsop-svcb-https-08, section 2.2. Note
 * that some keys don't require a value while others can have more than one.
 *
 * See svcparam_to_str() for the opposite functionality.
 */
static wdns_res
str_to_svcparam(ubuf *u, uint16_t key, char *val)
{
	char *tok, *endp = NULL;
	size_t val_len_offset, tok_len;
	uint16_t val_len = 0, tmp;

	assert(u != NULL);
	assert(key != spr_invalid);

	/*
	 * A 2 octet field containing the SvcParamKey in network byte order.
	 */
	tmp = htons(key);
	ubuf_append(u, (uint8_t *)&tmp, sizeof (tmp));

	/*
	 * 'no-default-alpn' must not have a value.
	 */
	if (key == spr_nd_alpn) {
		if (val != NULL) {
			return (wdns_res_parse_error);
		} else {
			return (wdns_res_success);
		}
	}

	/*
	 * A 2 octet field containing the length of the SvcParamValue also in
	 * network byte order. We set this to zero for now and fill it later
	 * once we know the length of the value.
	 */
	val_len_offset = ubuf_size(u);
	ubuf_append(u, (uint8_t*)&val_len, sizeof(val_len));

	/*
	 * Let's parse the value(s) now.
	 */
	switch (key) {
	case spr_mandatory:
		tok = strtok_r(val, ",", &endp);
		if (tok == NULL || *tok == '\0') {
			return (wdns_res_parse_error);
		}

		do {
			tmp = _wdns_str_to_svcparamkey(tok);
			if (tmp == spr_invalid) {
				return (wdns_res_parse_error);
			}
			tmp = htons(tmp);
			ubuf_append(u, (uint8_t *)&tmp, sizeof (tmp));
			val_len += sizeof(tmp);
		} while ((tok = strtok_r(NULL, ",", &endp)) != NULL);
		break;

	case spr_port: {
		unsigned long int tmpul;
		char *endport;

		/*
		 * The wire format of the SvcParamValue is the corresponding
		 * 2 octet numeric value in network byte order.
		 */
		tok = strtok_r(val, " ", &endp);
		if (tok == NULL || *tok == '\0') {
			return (wdns_res_parse_error);
		}

		tmpul = strtoul(tok, &endport, 10);
		if (*endport != '\0' || tmpul > UINT16_MAX) {
			return (wdns_res_parse_error);
		}

		tmp = htons((uint16_t)tmpul);
		ubuf_append(u, (uint8_t *)&tmp, sizeof (tmp));
		val_len = sizeof(tmp);
		break;
	}
	case spr_ech:
		/*
		 * In wire format, the value of the parameter is an
		 * ECHConfigList [ECH], including the redundant length prefix.
		 */
		tok = strtok_r(val, " ", &endp);
		if (tok == NULL || *tok == '\0') {
			return (wdns_res_parse_error);
		}

		tok_len = strlen(tok);
		if (tok_len > UINT8_MAX) {
			return (wdns_res_parse_error);
		}
		val_len = base64_str_to_ubuf(tok, tok_len, u);
		break;

	/*
	 * The wire format for IPv{4,6} hints is a sequence of IP addresses in
	 * network byte order. The list must not be empty.
	 */
	case spr_ipv4hint:
	case spr_ipv6hint: {
		unsigned char buf[16];
		int af = (key == spr_ipv4hint ? AF_INET : AF_INET6);
		size_t sz = (key == spr_ipv4hint ? 4 : 16);

		tok = strtok_r(val, ",", &endp);
		if (tok == NULL || *tok == '\0') {
			return (wdns_res_parse_error);
		}

		do {
			if (inet_pton(af, tok, buf) != 1) {
				return (wdns_res_parse_error);
			}

			ubuf_append(u, (uint8_t *)buf, sz);
			val_len += sz;
		} while ((tok = strtok_r(NULL, ",", &endp)) != NULL);
		break;
	}
	/*
	 * The wire format value for "alpn" consists of at least one "alpn-id"
	 * prefixed by its length as a single octet, and these length-value
	 * pairs are concatenated to form the SvcParamValue. These MUST exactly
	 * fill the SvcParamValue; otherwise, the SvcParamValue is malformed.
	 *
	 * We parse arbitrary keyNNNN=val pairs in a similar way, but without
	 * length-value paris (just one whole value).
	 *
	 * Note that we always wrap these two value types around double quotes
	 * in presentation format, as escaped spaces and commas are allowed.
	 */
	case spr_alpn:
	default: {
		uint8_t c, bytes;
		bool quoted;
		char *src;
		int len, i;
		ubuf *v;

		src = strdup(val);
		len = strlen(src);

		v = ubuf_new();
		bytes = 0;
		i = 0;

		if (src[i] == '"') {
			quoted = true;
			i++;
		} else {
			quoted = false;
		}

		for (; i < len; i++) {
			c = src[i];

			/* check for escaped characters first */
			if (c == '\\') {
				/* shouldn't happen, but just to be safe.. */
				if (++i >= len) {
					return (wdns_res_parse_error);
				}
				c = src[i];
				ubuf_append(v, &c, 1);
				bytes++;
				continue;
			}

			/*
			 * We're at the end of a param if we find:
			 *  - an unescaped, matching double quote;
			 *  - a blank space outside of double quotes.
			 */
			if (c == '"') {
				if (quoted) {
					break;
				} else {
					return (wdns_res_parse_error);
				}
			}
			if (c == ' ') {
			       	if (!quoted) {
					break;
				}
			}

			/*
			 * An unescaped comma separates two values. Add the
			 * current 'v' to 'u' and reset it for the next value.
			 */
			if (c == ',') {
				if (key == spr_alpn) {
					ubuf_append(u, (uint8_t *)&bytes,
					    sizeof (uint8_t));
				}
				ubuf_append(u, (uint8_t *)ubuf_data(v), bytes);

				ubuf_reset(v);
				val_len += bytes;

				if (key == spr_alpn) {
					val_len += sizeof (uint8_t);
				}
				bytes = 0;
			} else {
				ubuf_append(v, &c, 1);
				bytes++;
			}
		}

		if (bytes > 0) {
			val_len += bytes;

			if (key == spr_alpn) {
				val_len += sizeof (uint8_t);
				ubuf_append(u, (uint8_t *)&bytes,
				    sizeof (uint8_t));
			}

			ubuf_append(u, (uint8_t *)ubuf_data(v), bytes);
		}

		ubuf_destroy(&v);
		free(src);
		break;
		}
	}

	/*
	 * Set the correct length for the SvcParamValue.
	 */
	val_len = htons(val_len);
	(void) memcpy(&ubuf_data(u)[val_len_offset], &val_len,
	    sizeof (val_len));

	return (wdns_res_success);
}

static int
cmp_u16(const void *a, const void *b) {
	uint16_t u1 = *(uint16_t *)a;
	uint16_t u2 = *(uint16_t *)b;
	return u1 == u2 ? 0 : u1 > u2 ? 1 : -1;
}

wdns_res
_wdns_str_to_rdata_ubuf(ubuf *u, const char *str,
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
		if (!isspace(*str)) {
			res = wdns_res_parse_error;
			goto err;
		}
		while (*str && isspace(*str)) {
			str++;
		}

		const char * ptr = str;
		while (*ptr && !isspace(*ptr)) {
			if (!isdigit(*ptr)) {
				res = wdns_res_parse_error;
				goto err;
			}
			ptr++;
		}

		uint16_t rdlen;
		if (sscanf(str, "%hu", &rdlen) == 0) {
			res = wdns_res_parse_error;
			goto err;
		}
		str = ptr;

		size_t len = 0;
		while (*str) {
			uint8_t c;

			if (isspace(*str)) {
				str++;
				continue;
			}

			if (*(str+1) == 0) {
				res = wdns_res_parse_error;
				goto err;
			}
			if (!sscanf(str, "%02hhx", &c)) {
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_append(u, &c, 1);
			len++;
			str += 2;
		}
		if (len != rdlen) {
			res = wdns_res_parse_error;
			goto err;
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

			res = wdns_str_to_name_case(s, name);
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
			str += base64_str_to_ubuf(str, strlen(str), u);
			break;
		}

		case rdf_bytes_str: {
			size_t str_len = strlen(str);

			if (str_len >= 3 && str[0] == '"' && str[str_len - 1] == '"') {
				if (rdata_from_str_string((const uint8_t *)str, u) == 0) {
					res = wdns_res_parse_error;
					goto err;
				}
				str += str_len;
			} else {
				res = wdns_res_parse_error;
				goto err;
			}
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

			if (str == NULL || *str == 0) {
				res = wdns_res_parse_error;
				goto err;
			}

			end = strpbrk(str, " \t\r\n");

			uint8_t oclen = (128 - prefix_len) / 8;
			if (prefix_len % 8 != 0) {
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
				ubuf_append(u, addr + sizeof(addr) - oclen, oclen);
				str = end;
				if (prefix_len == 0 && str != NULL) {
					/*
					 * An A6 record with prefix length zero
					 * may not have a hostname component, so
					 * the text representation must end with the
					 * IPv6 address.
					 */
					while (isspace(*str))
						str++;
					if (*str != '\0') {
						res = wdns_res_parse_error;
						goto err;
					}
					str = NULL;
				}
			} else {
				if (prefix_len != 128) {
					res = wdns_res_parse_error;
					goto err;
				}
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

			/*
			 * The hashed owner name is presented as one base32 digit.
			 * A single byte would be two base32 digits, therefore we
			 * we can conclude the original data was zero bytes long.
			 */
			if (str_len == 1) {
				uint8_t c = 0;
				ubuf_append(u, &c, 1);
				str++;
				break;
			}

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

		case rdf_eui48: {
			uint8_t a[6] = {0};
			int ret;

			if (strlen(str) != strlen("01-02-03-04-05-06")) {
				res = wdns_res_parse_error;
				goto err;
			}
			for (int i = 0; i < 6; i++) {
				if (!isxdigit(str[3*i]) ||
				    !isxdigit(str[3*i + 1]) ||
				    (i < 5 && str[3*i + 2] != '-'))
				{
					res = wdns_res_parse_error;
					goto err;
				}
			}
			ret = sscanf(str, "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
			             &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);
			if (ret != 6) {
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_append(u, a, 6);
			str += strlen(str);
			break;
		}

		case rdf_eui64: {
			uint8_t a[8] = {0};
			int ret;

			if (strlen(str) != strlen("01-02-03-04-05-06-07-08")) {
				res = wdns_res_parse_error;
				goto err;
			}
			for (int i = 0; i < 8; i++) {
				if (!isxdigit(str[3*i]) ||
				    !isxdigit(str[3*i + 1]) ||
				    (i < 7 && str[3*i + 2] != '-'))
					{
						res = wdns_res_parse_error;
						goto err;
					}
			}
			ret = sscanf(str, "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
			             &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7]);
			if (ret != 8) {
				res = wdns_res_parse_error;
				goto err;
			}
			ubuf_append(u, a, 8);
			str += strlen(str);
			break;
		}

		case rdf_string: {
			const char *retp = NULL;

			res = str_to_ubuf(str, u, &retp);
			if (res != wdns_res_success) {
				goto err;
			}
			str = retp;
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

		case rdf_svcparams: {
			char *start, *eol;
			int prev_key = -1;

			eol = (char *)str;
			while (eol != NULL && *eol != '\0') {
				eol++;
			}

			start = (char *)str;

			while (start < eol) {
				char *key, *val, *end, *dup;
				uint16_t k;
				bool quotes;

				/* find out what key we're parsing */
				if (*start == ' ') {
					start++;
					continue;
				}

				key = start;
				val = start;

				/*
				 * The 'key' component of a parameter must end
				 * with a:
				 *  - '=' sign (preceeding a value);
				 *  - blank space or eol (if that particular
				 *    key doesn't require one).
				 */
				while (val != eol) {
					if (*val == '=' || *val == ' ') {
						break;
					}
					val++;
				}

				dup = strndup(key, val - key);
				k = _wdns_str_to_svcparamkey(dup);
				free(dup);

				/*
				 * Fail if the key:
				 *  - is invalid;
				 *  - it's numeric value is smaller than the
				 *    previous key (i.e they're not in
				 *    ascending order);
				 *  - doesn't require a value but has one;
				 *  - requires a value but has none.
				 */
				if (k == spr_invalid) {
					return (wdns_res_parse_error);
				}

				if (k <= prev_key) {
					return (wdns_res_parse_error);
				}

				prev_key = k;

				if (*val == ' ' || val == eol) {
					if (k != spr_nd_alpn) {
						return (wdns_res_success);
					}

					/* process spr_nd_alpn here */
					res = str_to_svcparam(u, k, NULL);
					if (res != wdns_res_success) {
						return (res);
					}

					start = val;
					continue;
				}

				if (*val != '=') {
					return (wdns_res_parse_error);
				}

				/* now parse the value */
				end = ++val;

				if (*end == '"') {
					quotes = true;
					end++;
				} else {
					quotes = false;
				}

				/* values always end with a blank space */
				while (end < eol) {
					if (*end == '"' && quotes) {
						/* end of double quotes */
						end++;
						break;
					}
					if (*end == ' ' && !quotes) {
						/* end of param */
						break;
					}
					end++;
				}

				dup = strndup(val, end - val);

				res = str_to_svcparam(u, k, dup);
				if (res != wdns_res_success) {
					return (res);
				}

				free(dup);
				start = end;
			}

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
					u16buf_destroy(&rrtypes);
					res = wdns_res_parse_error;
					goto err;
				}

				u16buf_add(rrtypes, my_rrtype);
				str = end;
			}
			qsort(u16buf_data(rrtypes), u16buf_size(rrtypes), sizeof(uint16_t), cmp_u16);

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
					/* Per RFC6840, do not write out an empty bitmap */
					if (bitmap_len > 0) {
						ubuf_append(u, (const uint8_t*)&window_block, sizeof(window_block));
						ubuf_append(u, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
						ubuf_append(u, (const uint8_t*)bitmap, bitmap_len);
						bitmap_len = 0;
					}
					memset(bitmap, 0, sizeof(bitmap));
					window_block = cur_window;
				}

				uint8_t offset = my_rrtype % 256;
				uint8_t byte = offset / 8;
				uint8_t bit = offset % 8;

				bitmap[byte] |= 0x80 >> bit;
				bitmap_len = 1 + byte;
			}
			if (bitmap_len != 0) {
				ubuf_append(u, (const uint8_t*)&window_block, sizeof(window_block));
				ubuf_append(u, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
				ubuf_append(u, (const uint8_t*)bitmap, bitmap_len);
			}

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
