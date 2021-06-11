/*
 * Copyright (c) 2009-2012, 2014, 2016, 2021 by Farsight Security, Inc.
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

/*
 * svcparam_key_validate() validates a SVCB svcparam key.
 * Note that we're not checking things like keys being in increasing
 * order or whether a mandatory key is actually present in the rdata.
 */
static bool
svcparam_key_validate(uint16_t key, uint16_t val_len, const uint8_t *val)
{
	bool res = true;
	uint8_t oclen, *ptr;

	switch (key) {
	case spr_mandatory:
		if ((val_len % 2) != 0) {
			res = false;
		}
		break;

	case spr_alpn: {
		if (val_len == 0) {
			res = false;
			break;
		}

		/*
		 * For now, we only need parse 'val' for spr_alpn and must
		 * rely on the caller to guarantee that we won't access
		 * more bytes than there actually are.
		 */
		ptr = (uint8_t *)val;

		while ((ptr - val) < val_len) {
			oclen = *ptr;
			ptr += 1 + oclen;
		}

		/*
		 * The pair(s) of [length,alpn] must exactly fill SvcParamValue.
		 */
		if (ptr - val != val_len) {
			res = false;
		}
		break;
	}

	case spr_nd_alpn:
		if (val_len != 0) {
			res = false;
		}
		break;

	case spr_port:
		if (val_len != 2) {
			res = false;
		}
		break;

	case spr_echconfig:
		break;

	case spr_ipv4hint:
		if ((val_len % 4) != 0) {
			res = false;
		}
		break;

	case spr_ipv6hint:
		if ((val_len % 16) != 0) {
			res = false;
		}
		break;

	case spr_invalid:
		res = false;
		break;

	default:
		break;
	}

	return (res);
}

/**
 * Parse the rdata component of a resource record.
 *
 * \param[out] rr resource record object whose ->rdata field will be populated
 * \param[in] p pointer to start of message
 * \param[in] eop end of message buffer
 * \param[in] rdata pointer to rdata
 * \param[in] rdlen
 */
wdns_res
_wdns_parse_rdata(wdns_rr_t *rr, const uint8_t *p, const uint8_t *eop,
		  const uint8_t *rdata, uint16_t rdlen)
{

#define advance_bytes(x) do { \
	if (src_bytes < ((signed) (x))) { \
		res = wdns_res_parse_error; \
		goto parse_error; \
	} \
	src += (x); \
	src_bytes -= (x); \
} while (0)

#define copy_bytes(x) do { \
	if (src_bytes < (x)) {\
		res = wdns_res_parse_error; \
		goto parse_error; \
	} \
	ubuf_append(u, src, x); \
	src += (x); \
	src_bytes -= (x); \
} while (0)

	ubuf *u;
	const record_descr *descr = NULL;
	const uint8_t *src;
	const uint8_t *t;
	ssize_t src_bytes;
	size_t len;
	uint8_t domain_name[WDNS_MAXLEN_NAME];
	uint8_t oclen;
	wdns_res res;

	u = ubuf_new();
	src = rdata;
	src_bytes = (ssize_t) rdlen;

	if (rr->rrtype < record_descr_len)
		descr = &record_descr_array[rr->rrtype];

	if (rr->rrtype >= record_descr_len ||
	    (descr != NULL && descr->types[0] == rdf_unknown))
	{
		/* unknown rrtype, treat generically */
		copy_bytes(src_bytes);
	} else if (descr != NULL &&
		   (descr->record_class == class_un ||
		    descr->record_class == rr->rrclass))
	{
		for (t = &descr->types[0]; *t != rdf_end; t++) {
			if (src_bytes == 0)
				break;

			switch (*t) {
			case rdf_name:
			case rdf_uname:
				res = wdns_unpack_name(p, eop, src, domain_name, &len);

				if (res != wdns_res_success) {
					goto parse_error;
				}
				src_bytes -= wdns_skip_name(&src, eop);
				if (src_bytes < 0) {
					res = wdns_res_out_of_bounds;
					goto parse_error;
				}
				ubuf_append(u, domain_name, len);
				break;

			case rdf_bytes:
			case rdf_bytes_b64:
			case rdf_bytes_str:
				copy_bytes(src_bytes);
				break;

			case rdf_int8:
				copy_bytes(1);
				break;

			case rdf_int16:
			case rdf_rrtype:
				copy_bytes(2);
				break;

			case rdf_int32:
			case rdf_ipv4:
				copy_bytes(4);
				break;

			case rdf_ipv6:
				copy_bytes(16);
				break;

			case rdf_eui48:
				copy_bytes(6);
				break;

			case rdf_eui64:
				copy_bytes(8);
				break;

			case rdf_string:
			case rdf_salt:
			case rdf_hash:
				oclen = *src;
				copy_bytes(oclen + 1);
				break;

			case rdf_repstring:
				while (src_bytes > 0) {
					oclen = *src;
					copy_bytes(oclen + 1);
				}
				break;

			case rdf_ipv6prefix:
				oclen = *src;
				if (oclen > 16U) {
					res = wdns_res_out_of_bounds;
					goto parse_error;
				}
				copy_bytes(oclen + 1);
				break;

			case rdf_type_bitmap: {
				uint8_t bitmap_len;

				while (src_bytes >= 2) {
					bitmap_len = *(src + 1);

					if (!(bitmap_len >= 1 && bitmap_len <= 32)) {
						res = wdns_res_out_of_bounds;
						goto parse_error;
					}

					if (bitmap_len <= (src_bytes - 2)) {
						copy_bytes(2 + bitmap_len);
					} else {
						res = wdns_res_out_of_bounds;
						goto parse_error;
					}
				}
				break;
			}

			case rdf_svcparams: {
				/*
				 * Wire format for the SvcParams portion of a
				 * SVCB or HTTPS message, parsed per section
				 * 2.2 of draft-ietf-dnsop-svcb-https.
				 */
				uint16_t key, val_len, kv_len;

				while (src_bytes > 0) {
					if (src_bytes < (int)(sizeof(key) +
					    sizeof(val_len))) {
						res = wdns_res_parse_error;
						goto parse_error;
					}

					/*
					 * A 2 octet field containing the
					 * SvcParamKey in network byte order.
					 */
					(void) memcpy(&key, src, sizeof(key));
					key = ntohs(key);

					/*
					 * A 2 octet field containing the length
					 * of the SvcParamValue also in network
					 * byte order.
					 */
					(void) memcpy(&val_len,
					    src + sizeof (key),
					    sizeof (val_len));
					val_len = ntohs(val_len);

					kv_len = sizeof(key) + sizeof(val_len) +
					    val_len;
					if (kv_len > src_bytes) {
						res = wdns_res_out_of_bounds;
						goto parse_error;
					}

					if (!svcparam_key_validate(key,
					    val_len, src + sizeof(key) +
					    sizeof(val_len))) {
						res = wdns_res_parse_error;
						goto parse_error;
					}

					copy_bytes(kv_len);
				}
				break;
			}

			default:
				fprintf(stderr, "%s: unhandled rdf type %u\n", __func__, *t);
				abort();
			}

		}
		if (src_bytes != 0) {
			res = wdns_res_out_of_bounds;
			goto parse_error;
		}
	} else {
		/* unknown rrtype, treat generically */
		copy_bytes(src_bytes);
	}

	/* load rr->rdata */
	len = ubuf_size(u);
	rr->rdata = my_malloc(sizeof(wdns_rdata_t) + len);
	rr->rdata->len = len;
	memcpy(rr->rdata->data, ubuf_cstr(u), len);
	ubuf_destroy(&u);

	return (wdns_res_success);

parse_error:
	ubuf_destroy(&u);
	return (res);

#undef advance_bytes
#undef copy_bytes
}
