/*
 * Copyright (c) 2010, 2012, 2019 by Farsight Security, Inc.
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

char *
wdns_message_to_str(wdns_message_t *m)
{
	const char *opcode;
	const char *rcode;
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();

	ubuf_append_cstr_lit(u, ";; ->>HEADER<<- ");

	opcode = wdns_opcode_to_str(WDNS_FLAGS_OPCODE(*m));
	if (opcode != NULL)
		ubuf_add_fmt(u, "opcode: %s", opcode);
	else
		ubuf_add_fmt(u, "opcode: %hu", WDNS_FLAGS_OPCODE(*m));

	rcode = wdns_rcode_to_str(WDNS_FLAGS_RCODE(*m));
	if (rcode != NULL)
		ubuf_add_fmt(u, ", rcode: %s", rcode);
	else
		ubuf_add_fmt(u, ", rcode: %hu", WDNS_FLAGS_RCODE(*m));

	ubuf_add_fmt(u,
		     ", id: %hu\n"
		     ";; flags:%s%s%s%s%s%s%s; "
		     "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
		     m->id,
		     WDNS_FLAGS_QR(*m) ? " qr" : "",
		     WDNS_FLAGS_AA(*m) ? " aa" : "",
		     WDNS_FLAGS_TC(*m) ? " tc" : "",
		     WDNS_FLAGS_RD(*m) ? " rd" : "",
		     WDNS_FLAGS_RA(*m) ? " ra" : "",
		     WDNS_FLAGS_AD(*m) ? " ad" : "",
		     WDNS_FLAGS_CD(*m) ? " cd" : "",
		     m->sections[0].n_rrs,
		     m->sections[1].n_rrs,
		     m->sections[2].n_rrs,
		     m->sections[3].n_rrs
	);

	if (m->edns.present) {
		char *edns_flags = m->edns.flags & 0x8000 ? " do" : "";
		ubuf_append_cstr_lit(u, "\n;; OPT PSEUDOSECTION:");
		/*
		 * RFC 6891 Section 6.1.4 and RFC 3225. Display "do" flag
		 * if the "DNSSEC OK" (D0) bit is set.
		 */
		ubuf_add_fmt(u, "\n; EDNS: version: %u, flags:%s; udp: %u", m->edns.version,
			edns_flags, m->edns.size);
		if (m->edns.options != NULL) {
			_wdns_rdata_to_ubuf(u, m->edns.options->data,
				m->edns.options->len, WDNS_TYPE_OPT, class_un);
		}
	}
	ubuf_append_cstr_lit(u, "\n;; QUESTION SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION);
	ubuf_append_cstr_lit(u, "\n;; ANSWER SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER);

	ubuf_append_cstr_lit(u, "\n;; AUTHORITY SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY);

	ubuf_append_cstr_lit(u, "\n;; ADDITIONAL SECTION:\n");
	_wdns_rrset_array_to_ubuf(u, &m->sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL);

	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}
