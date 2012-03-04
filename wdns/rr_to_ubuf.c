void
_wdns_rr_to_ubuf(ubuf *u, wdns_rr_t *rr, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];

	wdns_domain_to_str(rr->name.data, rr->name.len, name);
	dns_class = wdns_rrclass_to_str(rr->rrclass);
	dns_type = wdns_rrtype_to_str(rr->rrtype);

	if (sec == WDNS_MSG_SEC_QUESTION)
		ubuf_add_cstr(u, ";");
	
	ubuf_add_cstr(u, name);

	if (sec != WDNS_MSG_SEC_QUESTION)
		ubuf_add_fmt(u, " %u", rr->rrttl);

	if (dns_class)
		ubuf_add_fmt(u, " %s", dns_class);
	else
		ubuf_add_fmt(u, " CLASS%u", rr->rrclass);

	if (dns_type)
		ubuf_add_fmt(u, " %s", dns_type);
	else
		ubuf_add_fmt(u, " TYPE%u", rr->rrtype);

	if (sec != WDNS_MSG_SEC_QUESTION) {
		ubuf_add_cstr(u, " ");
		_wdns_rdata_to_ubuf(u, rr->rdata->data, rr->rdata->len, rr->rrtype, rr->rrclass);
	}
	ubuf_add_cstr(u, "\n");
}
