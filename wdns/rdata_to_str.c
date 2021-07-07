/*
 * Copyright (c) 2009-2010, 2012, 2015 by Farsight Security, Inc.
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
wdns_rdata_to_str(const uint8_t *rdata, uint16_t rdlen,
		  uint16_t rrtype, uint16_t rrclass)
{
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	_wdns_rdata_to_ubuf(u, rdata, rdlen, rrtype, rrclass);
	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}

wdns_res
wdns_str_to_rdata(const char * str, uint16_t rrtype, uint16_t rrclass,
		   uint8_t **rdata, size_t *rdlen) {
	ubuf *u;
	wdns_res res;

	u = ubuf_new();
	res = _wdns_str_to_rdata_ubuf(u, str, rrtype, rrclass);
	if (res == wdns_res_success) {
		ubuf_detach(u, (uint8_t **) rdata, rdlen);
	}
	ubuf_destroy(&u);
	return (res);
}
