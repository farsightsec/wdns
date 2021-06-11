/*
 * Copyright (c) 2009-2010, 2012-2013, 2019 by Farsight Security, Inc.
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
 * Convert a domain name to a human-readable string.
 *
 * \param[in] src domain name in wire format
 * \param[in] src_len length of domain name in bytes
 * \param[out] dst caller-allocated string buffer of size WDNS_PRESLEN_NAME
 *
 * \return Number of bytes read from src.
 */

size_t
wdns_domain_to_str(const uint8_t *src, size_t src_len, char *dst)
{
	size_t bytes_read = 0;
	size_t bytes_remaining = src_len;
	uint8_t oclen;

	assert(src != NULL);

	oclen = *src;
	while (bytes_remaining > 0 && oclen != 0) {
		src++;
		bytes_remaining--;

		bytes_read += oclen + 1 /* length octet */;

		while (oclen-- && bytes_remaining > 0) {
			uint8_t c = *src++;
			bytes_remaining--;

			if (c == '.' || c == '\\') {
				*dst++ = '\\';
				*dst++ = c;
			} else if (c >= '!' && c <= '~') {
				*dst++ = c;
			} else {
				snprintf(dst, 5, "\\%.3d", c);
				dst += 4;
			}
		}
		*dst++ = '.';
		oclen = *src;
	}
	if (bytes_read == 0)
		*dst++ = '.';
	bytes_read++;

	*dst = '\0';
	return (bytes_read);
}
