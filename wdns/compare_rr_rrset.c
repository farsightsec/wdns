/*
 * Copyright (c) 2009-2010, 2012 by Farsight Security, Inc.
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
 * Compare an RR to a RRset. An RR and an RRset compare true if the name, type,
 * and class match.
 *
 * This function does a case-insensitive name comparison.
 *
 * \param[in] rr the RR to compare
 * \param[in] rrset the RRset to compare
 *
 * \return true if the RR could be part of the RRset, false otherwise
 */

bool
wdns_compare_rr_rrset(const wdns_rr_t *rr, const wdns_rrset_t *rrset)
{
	if (rr->name.len == rrset->name.len &&
	    rr->rrtype == rrset->rrtype &&
	    rr->rrclass == rrset->rrclass)
	{
		wdns_name_t name_rr;
		wdns_name_t name_rrset;

		name_rr.len = rr->name.len;
		name_rr.data = alloca(name_rr.len);
		memcpy(name_rr.data, rr->name.data, name_rr.len);
		wdns_downcase_name(&name_rr);

		name_rrset.len = rrset->name.len;
		name_rrset.data = alloca(name_rrset.len);
		memcpy(name_rrset.data, rrset->name.data, name_rrset.len);
		wdns_downcase_name(&name_rrset);

		return (memcmp(name_rr.data, name_rrset.data, name_rr.len) == 0);
	}

	return (false);
}
