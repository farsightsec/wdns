void
_wdns_rrset_array_to_ubuf(ubuf *u, wdns_rrset_array_t *a, unsigned sec)
{
	for (unsigned i = 0; i < a->n_rrs; i++)
		_wdns_rr_to_ubuf(u, &a->rrs[i], sec);
}
