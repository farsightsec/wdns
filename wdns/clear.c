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

void
wdns_clear_rr(wdns_rr_t *rr)
{
	my_free(rr->name.data);
	my_free(rr->rdata);
}

void
wdns_clear_rrset(wdns_rrset_t *rrset)
{
	unsigned i;

	for (i = 0; i < rrset->n_rdatas; i++)
		my_free(rrset->rdatas[i]);
	my_free(rrset->name.data);
	my_free(rrset->rdatas);
	rrset->n_rdatas = 0;
}

void
wdns_clear_rrset_array(wdns_rrset_array_t *a)
{
	unsigned i;

	for (i = 0; i < a->n_rrs; i++)
		wdns_clear_rr(&a->rrs[i]);
	my_free(a->rrs);
	a->n_rrs = 0;

	for (i = 0; i < a->n_rrsets; i++)
		wdns_clear_rrset(&a->rrsets[i]);
	my_free(a->rrsets);
	a->n_rrsets = 0;
}

void
wdns_clear_message(wdns_message_t *m)
{
	unsigned i;

	my_free(m->edns.options);
	m->edns.present = false;
	for (i = 0; i < WDNS_MSG_SEC_MAX; i++)
		wdns_clear_rrset_array(&m->sections[i]);
}
