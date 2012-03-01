wdns_res
wdns_parse_message(wdns_message_t *m, const uint8_t *pkt, size_t len)
{
	const uint8_t *p = pkt;
	const uint8_t *pkt_end = pkt + len;
	size_t rrlen;
	uint16_t sec_counts[WDNS_MSG_SEC_MAX];
	wdns_rr_t rr;
	wdns_res res;

	memset(m, 0, sizeof(*m));

	if (len < WDNS_LEN_HEADER)
		return (wdns_res_len);

	WDNS_BUF_GET16(m->id, p);
	WDNS_BUF_GET16(m->flags, p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_QUESTION], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ANSWER], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_AUTHORITY], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ADDITIONAL], p);

	m->rcode = m->flags & 0xf;

	len -= WDNS_LEN_HEADER;

	for (unsigned sec = 0; sec < WDNS_MSG_SEC_MAX; sec++) {
		for (unsigned n = 0; n < sec_counts[sec]; n++) {
			if (p == pkt_end)
				return (wdns_res_success);

			res = _wdns_parse_message_rr(sec, pkt, pkt_end, p, &rrlen, &rr);
			if (res != wdns_res_success) {
				wdns_clear_message(m);
				return (res);
			}

			if (rr.rrtype == WDNS_TYPE_OPT) {
				res = _wdns_parse_edns(m, &rr);
				if (res != wdns_res_success)
					goto err;
			} else {
				res = _wdns_insert_rr_rrset_array(&m->sections[sec], &rr, sec);
				if (res != wdns_res_success)
					goto err;
			}

			p += rrlen;
		}
	}

	return (wdns_res_success);
err:
	wdns_clear_rr(&rr);
	wdns_clear_message(m);
	return (res);
}
