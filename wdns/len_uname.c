/**
 * Determine the length of an uncompressed wire format domain name.
 *
 * \param[in] p pointer to uncompressed domain name
 * \param[in] eop pointer to end of buffer containing name
 * \param[out] sz length of name
 *
 * \return wdns_res_success
 * \return wdns_res_overflow
 * \return wdns_res_invalid_length_octet
 */

wdns_res
wdns_len_uname(const uint8_t *p, const uint8_t *eop, size_t *sz)
{
	uint32_t olen = eop - p;
	uint32_t len = olen;

	if (p >= eop)
		return (wdns_res_overflow);

	while (len-- != 0) {
		uint8_t oclen;
		WDNS_BUF_GET8(oclen, p);

		if (oclen > 63 || oclen > len)
			return (wdns_res_invalid_length_octet);
		if (oclen == 0)
			break;

		WDNS_BUF_ADVANCE(p, len, oclen);
	}

	*sz = olen - len;
	return (wdns_res_success);
}
