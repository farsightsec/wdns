/*
 * Copyright (c) 2023 by Farsight Security, Inc.
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

#include <arpa/inet.h>

#include "libmy/my_num_to_str.h"


static inline const char *
_my_byte_to_hex_str(uint8_t byte, bool is_upper, char *dst)
{
	static const char *__hexchars = "0123456789abcdef";
	static const char *__HEXCHARS = "0123456789ABCDEF";
	const char *table = (is_upper ? __HEXCHARS : __hexchars);

	dst[0] = table[(byte >> 4) & 0xf];
	dst[1] = table[byte & 0xf];
	dst[2] = '\0';
	return dst;
}

const char *
my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst)
{
	size_t n;

	for (n = 0; n < len; n++)
		_my_byte_to_hex_str(src[n], is_upper, &dst[n * 2]);

	return dst;
}

const char *
my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst)
{
	uint16_t nval = htons(num);

	return my_bytes_to_hex_str((const uint8_t *) &nval, sizeof(nval), is_upper, dst);
}

const char *
my_uint64_to_str_padded(uint64_t num, uint32_t ndigits, char *dst)
{
	int ndx = ndigits - 1;

	while (ndigits > 0) {
		int digit = num % 10;
		dst[ndx] = '0' + digit;
		--ndx;
		--ndigits;
		num /= 10;
	}

	return dst;
}

size_t
my_uint64_to_str(uint64_t num, char *dst)
{
	uint64_t tmp = num;
	int ndx, left, ndigits = 0;

	do {
		ndigits++;
		tmp /= 10;
	} while (tmp != 0);

	left = ndigits;
	ndx = left - 1;

	while (left > 0) {
		int digit = num % 10;
		dst[ndx] = '0' + digit;
		--ndx;
		--left;
		num = num / 10;
	}

	dst[ndigits] = '\0';

	return ndigits;
}
