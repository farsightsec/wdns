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

wdns_res
wdns_downcase_rrset(wdns_rrset_t *rrset)
{
	wdns_res res;
	int i;

	wdns_downcase_name(&rrset->name);
	for (i = 0; i < rrset->n_rdatas; i++) {
		if (rrset->rdatas[i] != NULL) {
			res = wdns_downcase_rdata(rrset->rdatas[i],
						  rrset->rrtype, rrset->rrclass);
			if (res != wdns_res_success)
				return (res);
		}
	}

	return (wdns_res_success);
}
