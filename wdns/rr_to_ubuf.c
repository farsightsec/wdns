/*
 * Copyright (c) 2012, 2019 by Farsight Security, Inc.
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
_wdns_rr_to_ubuf(ubuf *u, wdns_rr_t *rr, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];

	wdns_domain_to_str(rr->name.data, rr->name.len, name);
	dns_class = wdns_rrclass_to_str(rr->rrclass);
	dns_type = wdns_rrtype_to_str(rr->rrtype);

	if (sec == WDNS_MSG_SEC_QUESTION)
		ubuf_add_cstr(u, ";");

	ubuf_add_cstr(u, name);

	if (sec != WDNS_MSG_SEC_QUESTION)
		ubuf_add_fmt(u, " %u", rr->rrttl);

	if (dns_class)
		ubuf_add_fmt(u, " %s", dns_class);
	else
		ubuf_add_fmt(u, " CLASS%u", rr->rrclass);

	if (dns_type)
		ubuf_add_fmt(u, " %s", dns_type);
	else
		ubuf_add_fmt(u, " TYPE%u", rr->rrtype);

	if (sec != WDNS_MSG_SEC_QUESTION) {
		ubuf_add_cstr(u, " ");
		_wdns_rdata_to_ubuf(u, rr->rdata->data, rr->rdata->len, rr->rrtype, rr->rrclass);
	}
	ubuf_add_cstr(u, "\n");
}
