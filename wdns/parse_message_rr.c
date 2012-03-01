/**
 * Parse a DNS resource record contained in a DNS message.
 *
 * \param[in] sec section the RR is contained in
 * \param[in] p the DNS message that contains the resource record
 * \param[in] eop pointer to end of buffer containing message
 * \param[in] data pointer to start of resource record
 * \param[out] rrsz number of wire bytes read from message
 * \param[out] rr parsed resource record
 */

wdns_res
_wdns_parse_message_rr(unsigned sec, const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wdns_rr_t *rr)
{
	const uint8_t *src = data;
	size_t len;
	uint16_t rdlen;
	uint8_t domain_name[WDNS_MAXLEN_NAME];
	wdns_res res;

	/* uncompress name */
	res = wdns_unpack_name(p, eop, src, domain_name, &len);
	if (res != wdns_res_success)
		return (res);

	/* copy name */
	rr->name.len = len;
	rr->name.data = malloc(len);
	if (rr->name.data == NULL)
		return (wdns_res_malloc);
	memcpy(rr->name.data, domain_name, len);

	/* skip name */
	wdns_skip_name(&src, eop);

	/* if this is a question RR, then we need 4 more bytes, rrtype (2) + rrclass (2). */
	/* if this is a response RR, then we need 10 more bytes, rrtype (2) + rrclass (2) +
	 * rrttl (4) + rdlen (2). */
	if (src + 4 > eop || (sec != WDNS_MSG_SEC_QUESTION && src + 10 > eop)) {
		res = wdns_res_parse_error;
		goto err;
	}

	/* rrtype */
	WDNS_BUF_GET16(rr->rrtype, src);

	/* rrclass */
	WDNS_BUF_GET16(rr->rrclass, src);

	/* finished parsing if this is a question RR */
	if (sec == WDNS_MSG_SEC_QUESTION) {
		rr->rrttl = 0;
		rr->rdata = NULL;
		*rrsz = (src - data);
		return (wdns_res_success);
	}

	/* rrttl */
	WDNS_BUF_GET32(rr->rrttl, src);

	/* rdlen */
	WDNS_BUF_GET16(rdlen, src);

	/* rdlen overflow check */
	if (src + rdlen > eop) {
		res = wdns_res_overflow;
		goto err;
	}

	/* parse and copy the rdata */
	res = _wdns_parse_rdata(rr, p, eop, src, rdlen);
	if (res != wdns_res_success)
		goto err;

	/* calculate the number of wire bytes that were read from the message */
	*rrsz = (src - data) + rdlen;

	return (wdns_res_success);

err:
	free(rr->name.data);
	rr->name.data = NULL;
	return (res);
}
