char *
wdns_rdata_to_str(const uint8_t *rdata, uint16_t rdlen,
		  uint16_t rrtype, uint16_t rrclass)
{
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	_wdns_rdata_to_ubuf(u, rdata, rdlen, rrtype, rrclass);
	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}

wdns_res
wdns_str_to_rdata(const char * str, uint16_t rrtype, uint16_t rrclass,
		   uint8_t **rdata, size_t *rdlen) {
	ubuf *u;
	wdns_res res;

	u = ubuf_new();
	res = _wdns_str_to_rdata_ubuf(u, str, rrtype, rrclass);
	if (res == wdns_res_success) {
		ubuf_detach(u, (uint8_t **) rdata, rdlen);
	}
	ubuf_destroy(&u);
	return (res);
}
