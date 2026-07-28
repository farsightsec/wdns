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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-unpack_name"

/*
 * A single-octet message consisting solely of a compression pointer's first
 * byte (0xC0). The second octet of the pointer would lie at eop, i.e. one
 * byte past the end of the message. This is a regression test for a bug
 * where wdns_unpack_name() read that missing second octet anyway instead of
 * detecting the truncation.
 */
static const uint8_t msg_truncated_pointer[] = { 0xC0 };

/* A compression pointer to the root label at offset 0. */
static const uint8_t msg_valid_pointer[] = { 0x00, 0xC0, 0x00 };

/* A compression pointer whose target is exactly one past the message. */
static const uint8_t msg_pointer_to_end[] = { 0x00, 0xC0, 0x03 };

/* An uncompressed name: www.example.com */
static const uint8_t msg_uncompressed[] = {
	3, 'w', 'w', 'w',
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	3, 'c', 'o', 'm',
	0
};

struct test {
	const char *descr;
	const uint8_t *msg;
	size_t msglen;
	size_t name_offset;
	wdns_res expected_res;
	const uint8_t *expected_name;
	size_t expected_len;
};

static struct test tdata[] = {
	{
		"compression pointer truncated at end of message",
		msg_truncated_pointer, sizeof(msg_truncated_pointer), 0,
		wdns_res_out_of_bounds, NULL, 0
	},
	{
		"compression pointer to root label",
		msg_valid_pointer, sizeof(msg_valid_pointer), 1,
		wdns_res_success, msg_valid_pointer, 1
	},
	{
		"compression pointer target at end of message",
		msg_pointer_to_end, sizeof(msg_pointer_to_end), 1,
		wdns_res_invalid_compression_pointer, NULL, 0
	},
	{
		"uncompressed name",
		msg_uncompressed, sizeof(msg_uncompressed), 0,
		wdns_res_success, msg_uncompressed, sizeof(msg_uncompressed)
	},
	{
		"uncompressed name with terminating label after eop",
		msg_uncompressed, sizeof(msg_uncompressed)-1, 0,
		wdns_res_out_of_bounds, NULL, 0
	},
	{ NULL, NULL, 0, 0, wdns_res_success, NULL, 0 }
};

static size_t
test_unpack_name(void)
{
	ubuf *u;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);

	for (cur = tdata; cur->descr != NULL; cur++) {
		uint8_t dst[WDNS_MAXLEN_NAME];
		size_t len = 0;
		wdns_res res;

		ubuf_reset(u);

		res = wdns_unpack_name(cur->msg, cur->msg + cur->msglen,
					cur->msg + cur->name_offset, dst, &len);

		if (res != cur->expected_res) {
			ubuf_add_fmt(u, "FAIL %s: res=%s != %s",
				     cur->descr,
				     wdns_res_to_str(res),
				     wdns_res_to_str(cur->expected_res));
			failures++;
		} else if (res == wdns_res_success &&
			   (len != cur->expected_len ||
			    memcmp(dst, cur->expected_name, len) != 0))
		{
			ubuf_add_fmt(u, "FAIL %s: len=%" PRIu64 " != %" PRIu64 " or value mismatch",
				     cur->descr, (uint64_t)len, (uint64_t)cur->expected_len);
			failures++;
		} else {
			ubuf_add_fmt(u, "PASS %s: res=%s",
				     cur->descr, wdns_res_to_str(res));
		}

		fprintf(stderr, "%s\n", ubuf_cstr(u));
	}

	ubuf_destroy(&u);
	return failures;
}

int main(void)
{
	int ret = 0;

	ret |= check(test_unpack_name(), "test_unpack_name", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
