/*
 * Copyright (c) 2009-2010, 2012, 2014 by Farsight Security, Inc.
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
 * Parse a serialized wdns_rrset_t.
 *
 * \param[out] rrset parsed RRset
 * \param[in] buf serialized RRset
 * \param[in] sz length of buf
 */

wdns_res
wdns_deserialize_rrset(wdns_rrset_t *rrset, const uint8_t *buf, size_t sz)
{

#define copy_bytes(ptr, len) do { \
	if (bytes_read + len > sz) { \
		wdns_clear_rrset(rrset); \
		return (wdns_res_overflow); \
	} \
	memcpy(ptr, buf, len); \
	buf += len; \
	bytes_read += len; \
} while(0)

	size_t bytes_read = 0;

	memset(rrset, 0, sizeof(*rrset));

	/* length of name */
	copy_bytes(&rrset->name.len, 1);

	/* name */
	rrset->name.data = my_malloc(rrset->name.len);
	copy_bytes(rrset->name.data, rrset->name.len);

	/* type */
	copy_bytes(&rrset->rrtype, 2);

	/* class */
	copy_bytes(&rrset->rrclass, 2);

	/* ttl */
	copy_bytes(&rrset->rrttl, 4);

	/* number of rdatas */
	copy_bytes(&rrset->n_rdatas, 2);

	/* rdatas */
	rrset->rdatas = my_calloc(1, sizeof(void *) * rrset->n_rdatas);
	for (size_t i = 0; i < rrset->n_rdatas; i++) {
		uint16_t rdlen;

		copy_bytes(&rdlen, 2);
		rrset->rdatas[i] = my_malloc(sizeof(rrset->rdatas[i]) + rdlen);
		rrset->rdatas[i]->len = rdlen;
		copy_bytes(&rrset->rdatas[i]->data, rdlen);
	}

	return (wdns_res_success);
}
