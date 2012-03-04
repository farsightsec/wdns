char *
wdns_rr_to_str(wdns_rr_t *rr, unsigned sec)
{
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	_wdns_rr_to_ubuf(u, rr, sec);
	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}
