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
_wdns_parse_edns(wdns_message_t *m, wdns_rr_t *rr)
{
	m->edns.present = true;
	m->edns.size = rr->rrclass;
	m->edns.version = (rr->rrttl >> 16) & 0xFF;
	m->edns.flags = rr->rrttl & 0xFFFF;
	m->edns.options = rr->rdata;
	rr->rdata = NULL;

	m->rcode |= (rr->rrttl >> 16) & 0xFF00;

	wdns_clear_rr(rr);

	return (wdns_res_success);
}
