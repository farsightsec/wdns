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

wdns_res
wdns_left_chop(wdns_name_t *name, wdns_name_t *chop)
{
	uint8_t oclen;

	oclen = name->data[0];

	if (oclen == 0 && name->len == 1) {
		chop->len = 1;
		chop->data = name->data;
		return (wdns_res_success);
	}

	if (oclen > name->len - 1)
		return (wdns_res_name_overflow);

	chop->len = name->len - oclen - 1;
	chop->data = name->data + oclen + 1;
	return (wdns_res_success);
}
