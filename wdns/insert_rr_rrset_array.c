/*
 * Copyright (c) 2009-2010, 2012, 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Insert an RR into an RRset array.
 *
 * This function is destructive.  No copying is performed; instead the RR's name
 * and/or rdata fields are detached from the RR and given to an RRset in the
 * RRset array.  wdns_clear_rr() is called on the RR object.
 *
 * \return wdns_res_success
 * \return wdns_res_malloc
 */

wdns_res
_wdns_insert_rr_rrset_array(wdns_rrset_array_t *a, wdns_rr_t *rr, unsigned sec)
{
	bool found_rrset = false;
	wdns_rdata_t *rdata;
	wdns_rr_t *new_rr;
	wdns_rrset_t *rrset;
	unsigned i;

	/* add to RR array */
	a->n_rrs += 1;
	a->rrs = my_realloc(a->rrs, a->n_rrs * sizeof(wdns_rr_t));
	new_rr = &a->rrs[a->n_rrs - 1];
	new_rr->rrttl = rr->rrttl;
	new_rr->rrtype = rr->rrtype;
	new_rr->rrclass = rr->rrclass;
	new_rr->name.len = rr->name.len;

	/* copy the owner name */
	new_rr->name.data = my_malloc(rr->name.len);
	memcpy(new_rr->name.data, rr->name.data, rr->name.len);

	/* copy the rdata */
	if (sec != WDNS_MSG_SEC_QUESTION) {
		new_rr->rdata = my_malloc(sizeof(wdns_rdata_t) + rr->rdata->len);
		new_rr->rdata->len = rr->rdata->len;
		memcpy(new_rr->rdata->data, rr->rdata->data, rr->rdata->len);
	} else {
		new_rr->rdata = NULL;
	}

	/* iterate over RRset array backwards */
	for (i = a->n_rrsets; i > 0; i--) {
		if (sec == WDNS_MSG_SEC_QUESTION)
			break;

		rrset = &a->rrsets[i - 1];

		if (wdns_compare_rr_rrset(rr, rrset)) {
			/* this RR is part of the RRset */
			rrset->n_rdatas += 1;
			rrset->rdatas = my_realloc(rrset->rdatas,
						   rrset->n_rdatas * sizeof(*(rrset->rdatas)));

			/* detach the rdata from the RR and give it to the RRset */
			rdata = rr->rdata;
			rr->rdata = NULL;
			rrset->rdatas[rrset->n_rdatas - 1] = rdata;

			/* use the lowest TTL out of the RRs for the RRset itself */
			if (rr->rrttl < rrset->rrttl)
				rrset->rrttl = rr->rrttl;

			found_rrset = true;
			break;
		}
	}

	if (found_rrset == false) {
		/* create a new RRset */
		a->n_rrsets += 1;
		a->rrsets = my_realloc(a->rrsets, a->n_rrsets * sizeof(wdns_rrset_t));
		rrset = &a->rrsets[a->n_rrsets - 1];
		memset(rrset, 0, sizeof(*rrset));

		/* copy fields from the RR */
		rrset->rrttl = rr->rrttl;
		rrset->rrtype = rr->rrtype;
		rrset->rrclass = rr->rrclass;

		/* add rdata */
		if (sec != WDNS_MSG_SEC_QUESTION) {
			rrset->n_rdatas = 1;
			rrset->rdatas = my_malloc(sizeof(*(rrset->rdatas)));
		}

		/* detach the owner name from the RR and give it to the RRset */
		rrset->name.len = rr->name.len;
		rrset->name.data = rr->name.data;
		rr->name.len = 0;
		rr->name.data = NULL;

		/* detach the rdata from the RR and give it to the RRset */
		if (sec != WDNS_MSG_SEC_QUESTION) {
			rdata = rr->rdata;
			rr->rdata = NULL;
			rrset->rdatas[0] = rdata;
		}
	}

	wdns_clear_rr(rr);
	return (wdns_res_success);
}
