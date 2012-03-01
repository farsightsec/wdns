wdns_res
wdns_downcase_rrset(wdns_rrset_t *rrset)
{
	wdns_res res;

	wdns_downcase_name(&rrset->name);
	for (int i = 0; i < rrset->n_rdatas; i++) {
		if (rrset->rdatas[i] != NULL) {
			res = wdns_downcase_rdata(rrset->rdatas[i],
						  rrset->rrtype, rrset->rrclass);
			if (res != wdns_res_success)
				return (res);
		}
	}

	return (wdns_res_success);
}
