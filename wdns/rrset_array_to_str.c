char *
wdns_rrset_array_to_str(wdns_rrset_array_t *a, unsigned sec)
{
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	_wdns_rrset_array_to_ubuf(u, a, sec);
	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}
