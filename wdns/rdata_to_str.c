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
