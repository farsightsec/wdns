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
 * Count the number of labels in an uncompressed domain name.
 *
 * \param[in] name
 * \param[out] nlabels
 *
 * \return wdns_res_success
 * \return wdns_res_invalid_length_octet
 * \return wdns_res_name_overflow
 */

wdns_res
wdns_count_labels(wdns_name_t *name, size_t *nlabels)
{
	uint8_t c, *data;

	*nlabels = 0;
	data = name->data;

	while ((c = *data++) != 0) {
		if (c <= 63) {
			*nlabels += 1;
			data += c;
			if (data - name->data > name->len)
				return (wdns_res_name_overflow);
		} else {
			return (wdns_res_invalid_length_octet);
		}
	}

	return (wdns_res_success);
}
