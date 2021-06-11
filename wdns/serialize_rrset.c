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

/**
 * Serialize a wdns_rrset_t.
 *
 * \param[in] rrset the RRset to serialize
 * \param[out] buf the output buffer (may be NULL)
 * \param[out] sz serialized length (may be NULL)
 *
 * \return wdns_res_success
 */

wdns_res
wdns_serialize_rrset(const wdns_rrset_t *rrset, uint8_t *buf, size_t *sz)
{
	if (sz) {
		*sz = 1;			/* length of name */
		*sz += rrset->name.len;		/* name */
		*sz += 2;			/* type */
		*sz += 2;			/* class */
		*sz += 4;			/* ttl */
		*sz += 2;			/* number of rdatas */

		for (size_t i = 0; i < rrset->n_rdatas; i++) {
			/* rdata length */
			*sz += 2;

			/* rdata */
			*sz += rrset->rdatas[i]->len;
		}
	}

	if (buf) {
		/* length of name */
		memcpy(buf, &rrset->name.len, 1);
		buf += 1;

		/* name */
		memcpy(buf, rrset->name.data, rrset->name.len);
		buf += rrset->name.len;

		/* type */
		memcpy(buf, &rrset->rrtype, 2);
		buf += 2;

		/* class */
		memcpy(buf, &rrset->rrclass, 2);
		buf += 2;

		/* ttl */
		memcpy(buf, &rrset->rrttl, 4);
		buf += 4;

		/* number of rdatas */
		memcpy(buf, &rrset->n_rdatas, 2);
		buf += 2;

		for (size_t i = 0; i < rrset->n_rdatas; i++) {
			uint16_t rdlen = rrset->rdatas[i]->len;

			/* rdata length */
			memcpy(buf, &rdlen, 2);
			buf += 2;

			/* rdata */
			memcpy(buf, &rrset->rdatas[i]->data, rdlen);
			buf += rdlen;
		}
	}

	return (wdns_res_success);
}
