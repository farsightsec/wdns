/*
 * Copyright (c) 2026 DomainTools LLC
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

#include "test-common.h"

#include "libmy/b64_decode.h"
#include "libmy/b64_decode.c"

#include <string.h>

#define NAME "test-b64_decode"

/*
 * base64_decode_value() must report every non-alphabet octet as negative,
 * whatever the sign of a plain char is on this platform.  base64_decode_block()
 * relies on that to skip padding and whitespace.
 */
static size_t
test_decode_value(void) {
	size_t failures = 0;
	size_t i;
	static const struct {
		char input;
		int expected;
	} testdata[] = {
		{ 'A', 0 },
		{ 'Z', 25 },
		{ 'a', 26 },
		{ 'z', 51 },
		{ '0', 52 },
		{ '9', 61 },
		{ '+', 62 },
		{ '/', 63 },
		{ '=', -2 },
		{ ' ', -1 },
		{ '\t', -1 },
		{ '\n', -1 },
		{ '\r', -1 },
		{ '-', -1 },
		{ '{', -1 },	/* one past the end of the decoding table */
		{ '\x7f', -1 },
		{ '\xff', -1 },
	};

	for (i = 0; i < sizeof(testdata)/sizeof(testdata[0]); i++) {
		int res = base64_decode_value(testdata[i].input);

		if (res == testdata[i].expected) {
			fprintf(stderr, "PASS %zu: base64_decode_value(0x%02x) = %d\n",
				i, (unsigned char) testdata[i].input, res);
		} else {
			fprintf(stderr, "FAIL %zu: base64_decode_value(0x%02x) = %d != %d\n",
				i, (unsigned char) testdata[i].input, res,
				testdata[i].expected);
			failures++;
		}
	}

	return (failures);
}

/*
 * Decoding must ignore padding and embedded whitespace.  DNSKEY, CDNSKEY,
 * RRSIG and OPENPGPKEY presentation format all carry both.
 */
static size_t
test_decode_block(void) {
	size_t failures = 0;
	size_t i;
	static const struct {
		const char *input;
		const char *expected;
		size_t elen;
	} testdata[] = {
		{ "AQIDBAUGBwg=", "\x01\x02\x03\x04\x05\x06\x07\x08", 8 },
		{ "ZGVhZGJlZWY=", "deadbeef", 8 },
		{ "ZGVhZGJlZWY==", "deadbeef", 8 },
		{ "ZGVh ZGJl ZWY=", "deadbeef", 8 },
		{ "ZGVhZGJl\nZWY=", "deadbeef", 8 },
		{ "ZGVhZGJl\r\n\tZWY=", "deadbeef", 8 },
		{ "  ZGVhZGJlZWY=  ", "deadbeef", 8 },
		{ "AA==", "\x00", 1 },
		{ "", "", 0 },
	};

	for (i = 0; i < sizeof(testdata)/sizeof(testdata[0]); i++) {
		base64_decodestate b64;
		char buf[64];
		int len;

		memset(buf, 0, sizeof(buf));
		base64_init_decodestate(&b64);
		len = base64_decode_block(testdata[i].input,
					  strlen(testdata[i].input),
					  buf, &b64);

		if (len == (int) testdata[i].elen &&
		    memcmp(buf, testdata[i].expected, testdata[i].elen) == 0)
		{
			fprintf(stderr, "PASS %zu: base64_decode_block(\"%s\") len %d\n",
				i, testdata[i].input, len);
		} else {
			ubuf *u = ubuf_init(64);

			escape(u, (const uint8_t *) buf, len < 0 ? 0 : (size_t) len);
			fprintf(stderr, "FAIL %zu: base64_decode_block(\"%s\") len %d != %zu value=%s\n",
				i, testdata[i].input, len, testdata[i].elen,
				ubuf_cstr(u));
			ubuf_destroy(&u);
			failures++;
		}
	}

	return (failures);
}

int main (void) {
	int ret = 0;

	ret |= check(test_decode_value(), "test_decode_value", NAME);
	ret |= check(test_decode_block(), "test_decode_block", NAME);

	if (ret)
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}
