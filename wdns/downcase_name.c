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

/**
 * Downcase a wdns_name_t.
 *
 * \param[in] name the name to downcase
 */

void
wdns_downcase_name(wdns_name_t *name)
{
	uint8_t *p = name->data;
	uint16_t len = name->len;

	while (len-- != 0) {
		if (*p >= 'A' && *p <= 'Z')
			*p |= 0x20;
		p++;
	}
}
