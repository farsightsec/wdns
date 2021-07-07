/*
 * Copyright (c) 2011-2012, 2014 by Farsight Security, Inc.
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
wdns_reverse_name(const uint8_t *name, size_t len_name, uint8_t *rev_name) {
	const uint8_t *p;
	size_t len;
	size_t total_len = 0;

	p = name;
	memset(rev_name, 0, len_name);
	rev_name += len_name - 1;

	while ((len = *p) != '\x00') {
		len += 1;
		total_len += len;
		if (total_len > len_name) {
			return (wdns_res_out_of_bounds);
		}
		rev_name -= len;
		memcpy(rev_name, p, len);
		p += len;
	}

	return (wdns_res_success);
}
