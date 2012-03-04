char *
wdns_message_to_str(wdns_message_t *m)
{
	const char *opcode;
	const char *rcode;
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	
	ubuf_add_cstr(u, ";; ->>HEADER<<- ");

	opcode = wdns_opcode_to_str(WDNS_FLAGS_OPCODE(*m));
	if (opcode != NULL)
		ubuf_add_fmt(u, "opcode: %s", opcode);
	else
		ubuf_add_fmt(u, "opcode: %hu", WDNS_FLAGS_OPCODE(*m));

	rcode = wdns_rcode_to_str(WDNS_FLAGS_RCODE(*m));
	if (rcode != NULL)
		ubuf_add_fmt(u, ", rcode: %s", rcode);
	else
		ubuf_add_fmt(u, ", rcode: %hu", WDNS_FLAGS_RCODE(*m));

	ubuf_add_fmt(u,
		     ", id: %hu\n"
		     ";; flags:%s%s%s%s%s%s%s; "
		     "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
		     m->id,
		     WDNS_FLAGS_QR(*m) ? " qr" : "",
		     WDNS_FLAGS_AA(*m) ? " aa" : "",
		     WDNS_FLAGS_TC(*m) ? " tc" : "",
		     WDNS_FLAGS_RD(*m) ? " rd" : "",
		     WDNS_FLAGS_RA(*m) ? " ra" : "",
		     WDNS_FLAGS_AD(*m) ? " ad" : "",
		     WDNS_FLAGS_CD(*m) ? " cd" : "",
		     m->sections[0].n_rrs,
		     m->sections[1].n_rrs,
		     m->sections[2].n_rrs,
		     m->sections[3].n_rrs
	);

	ubuf_add_cstr(u, "\n;; QUESTION SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION);

	ubuf_add_cstr(u, "\n;; ANSWER SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER);

	ubuf_add_cstr(u, "\n;; AUTHORITY SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY);

	ubuf_add_cstr(u, "\n;; ADDITIONAL SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL);

	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}
