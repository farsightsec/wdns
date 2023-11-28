/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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
_wdns_rrset_to_ubuf(ubuf *u, wdns_rrset_t *rrset, unsigned sec)
{
	unsigned i, n_rdatas;

	if (sec == WDNS_MSG_SEC_QUESTION)
		n_rdatas = 1;
	else
		n_rdatas = rrset->n_rdatas;

	for (i = 0; i < n_rdatas; i++) {
		wdns_rr_t rr;
		rr.rrttl = rrset->rrttl;
		rr.rrtype = rrset->rrtype;
		rr.rrclass = rrset->rrclass;
		rr.name.len = rrset->name.len;
		rr.name.data = rrset->name.data;
		rr.rdata = rrset->rdatas[i];
		_wdns_rr_to_ubuf(u, &rr, sec);
	}
}
