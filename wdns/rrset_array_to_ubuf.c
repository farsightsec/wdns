/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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
_wdns_rrset_array_to_ubuf(ubuf *u, wdns_rrset_array_t *a, unsigned sec)
{
	for (unsigned i = 0; i < a->n_rrs; i++)
		_wdns_rr_to_ubuf(u, &a->rrs[i], sec);
}
