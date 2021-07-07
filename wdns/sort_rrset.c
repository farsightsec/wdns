/*
 * Copyright (c) 2009, 2012 by Farsight Security, Inc.
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

static int
rdata_cmp(const void *e1, const void *e2)
{
	const wdns_rdata_t *r1 = *((wdns_rdata_t **) e1);
	const wdns_rdata_t *r2 = *((wdns_rdata_t **) e2);

	if (r1->len < r2->len) {
		return (-1);
	} else if (r1->len > r2->len) {
		return (1);
	} else {
		return (memcmp(r1->data, r2->data, r1->len));
	}
}

/**
 * Sort the rdata set of an RRset.
 *
 * \return wdns_res_success
 */

wdns_res
wdns_sort_rrset(wdns_rrset_t *rrset)
{
	if (rrset->n_rdatas > 1)
		qsort(&rrset->rdatas[0],
		      rrset->n_rdatas,
		      sizeof(rrset->rdatas[0]),
		      rdata_cmp);
	return (wdns_res_success);
}
