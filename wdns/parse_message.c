/*
 * Copyright (c) 2009-2012, 2014 by Farsight Security, Inc.
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
wdns_parse_message(wdns_message_t *m, const uint8_t *pkt, size_t len)
{
	const uint8_t *p = pkt;
	const uint8_t *pkt_end = pkt + len;
	size_t rrlen;
	uint16_t sec_counts[WDNS_MSG_SEC_MAX];
	wdns_rr_t rr;
	wdns_res res;

	memset(m, 0, sizeof(*m));

	if (len < WDNS_LEN_HEADER)
		return (wdns_res_len);

	WDNS_BUF_GET16(m->id, p);
	WDNS_BUF_GET16(m->flags, p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_QUESTION], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ANSWER], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_AUTHORITY], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ADDITIONAL], p);

	m->rcode = m->flags & 0xf;

	for (unsigned sec = 0; sec < WDNS_MSG_SEC_MAX; sec++) {
		for (unsigned n = 0; n < sec_counts[sec]; n++) {
			if (p == pkt_end)
				return (wdns_res_success);

			res = _wdns_parse_message_rr(sec, pkt, pkt_end, p, &rrlen, &rr);
			if (res != wdns_res_success) {
				wdns_clear_message(m);
				return (res);
			}

			/*
			 * An uncommon occurrence is the presence of multiple
			 * OPT records. In this case, we apply the first one to
			 * the DNS header and treat all subsequent ones as
			 * ordinary resource records.
			 */
			if (rr.rrtype == WDNS_TYPE_OPT && !m->edns.present) {
				res = _wdns_parse_edns(m, &rr);
				if (res != wdns_res_success)
					goto err;
			} else {
				res = _wdns_insert_rr_rrset_array(&m->sections[sec], &rr, sec);
				if (res != wdns_res_success)
					goto err;
			}

			p += rrlen;
		}
	}

	return (wdns_res_success);
err:
	wdns_clear_rr(&rr);
	wdns_clear_message(m);
	return (res);
}
