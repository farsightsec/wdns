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

static const char *hexchars = "0123456789abcdef";
static const char *HEXCHARS = "0123456789ABCDEF";


static inline const char *
_my_uint8_to_hex_str_padded(uint8_t num, const char * src, char *dst) {
	dst[0] = src[(num >> 4) & 0xf];
	dst[1] = src[num & 0xf];
	dst[2] = '\0';
	return dst;
}
const char *
my_uint8_to_hex_str_padded(uint8_t num, char *dst)
{
	return _my_uint8_to_hex_str_padded(num, hexchars, dst);
}

const char *
my_uint8_to_hex_STR_padded(uint8_t num, char *dst)
{
	return _my_uint8_to_hex_str_padded(num, HEXCHARS, dst);
}

const char *
my_uint16_to_hex_str(uint16_t num, char *dst)
{
	uint16_t ndx = 0;
	char *ptr = dst;

	if (num >= 0x1000) {
		ndx = 3;
	} else if (num >= 0x0100) {
		ndx = 2;
	} else if (num >= 0x0010) {
		ndx = 1;
	}

	do {
		uint32_t digit = num & 0xf;
		dst[ndx] = hexchars[digit];
		--ndx;
		ptr++;
		num >>= 4;
	} while (num != 0);


	return ptr;
}

const char *
my_uint64_to_str_padded(uint64_t num, int size, char *dst)
{
	int ndx = size - 1;

	while (size > 0) {
		int digit = num % 10;
		dst[ndx] = '0' + digit;
		--ndx;
		--size;
		num /= 10;
	}

	return dst;
}

size_t
my_uint64_to_str(uint64_t num, char *buffer)
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
		buffer[ndx] = '0' + digit;
		--ndx;
		--left;
		num = num / 10;
	}

	buffer[ndigits] = '\0';

	return ndigits;
}