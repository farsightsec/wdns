void
wdns_clear_rr(wdns_rr_t *rr)
{
	my_free(rr->name.data);
	my_free(rr->rdata);
}

void
wdns_clear_rrset(wdns_rrset_t *rrset)
{
	for (unsigned i = 0; i < rrset->n_rdatas; i++)
		my_free(rrset->rdatas[i]);
	my_free(rrset->name.data);
	my_free(rrset->rdatas);
	rrset->n_rdatas = 0;
}

void
wdns_clear_rrset_array(wdns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrs; i++)
		wdns_clear_rr(&a->rrs[i]);
	my_free(a->rrs);
	a->n_rrs = 0;

	for (unsigned i = 0; i < a->n_rrsets; i++)
		wdns_clear_rrset(&a->rrsets[i]);
	my_free(a->rrsets);
	a->n_rrsets = 0;
}

void
wdns_clear_message(wdns_message_t *m)
{
	my_free(m->edns.options);
	m->edns.present = false;
	for (unsigned i = 0; i < WDNS_MSG_SEC_MAX; i++)
		wdns_clear_rrset_array(&m->sections[i]);
}
