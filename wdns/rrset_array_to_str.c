/*
 * Copyright (c) 2010, 2012 by Farsight Security, Inc.
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
wdns_rrset_array_to_str(wdns_rrset_array_t *a, unsigned sec)
{
	char *ret;
	size_t retsz;
	ubuf *u;

	u = ubuf_new();
	_wdns_rrset_array_to_ubuf(u, a, sec);
	ubuf_cterm(u);
	ubuf_detach(u, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&u);
	return (ret);
}
