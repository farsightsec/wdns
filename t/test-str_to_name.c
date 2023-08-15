/*
 * Copyright (c) 2022-2023 DomainTools LLC
 * Copyright (c) 2015-2016, 2018 by Farsight Security, Inc.
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
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-str_to_name"

typedef wdns_res (*fp)(char *, wdns_name_t *);

struct test {
	char *input;
	fp func;
	const uint8_t *expected;
	size_t expected_len;
	wdns_res expected_res;
};

struct test tdata[] = {
	{ "", (fp)wdns_str_to_name, (const uint8_t *)"\x00", 1, wdns_res_success},
	{ ".", (fp)wdns_str_to_name, (const uint8_t *)"\x00", 1, wdns_res_success},
	{ "fsi.io", (fp)wdns_str_to_name, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success},
	{ "fsi.io.", (fp)wdns_str_to_name, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success},
	{ "FsI.io", (fp)wdns_str_to_name_case, (const uint8_t*)"\x03""FsI\x02io\x00", 8, wdns_res_success},
	{ "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x61xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.",
	  (fp)wdns_str_to_name,
	  (const uint8_t *)"\x3Fx63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
			   "\x3Fx63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
			   "\x3Fx63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
			   "\x3Dx61xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x00",
	  255, wdns_res_success },
	{ "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x63xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
	  "x62xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.",
	  (fp)wdns_str_to_name, (const uint8_t *)"", 0, wdns_res_name_overflow },
	{ 0 }
};


static size_t
test_str_to_name(void)
{
	ubuf *u;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);

	for(cur = tdata; cur->input != NULL; cur++) {
		wdns_name_t name;
		wdns_res res;

		ubuf_reset(u);

		res = cur->func(cur->input, &name);

		if (res != cur->expected_res) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " res=%s != %s",
					wdns_res_to_str(res),
					wdns_res_to_str(cur->expected_res));

			if (res == wdns_res_success) {
				ubuf_add_cstr(u, " value=");
				escape(u, name.data, name.len);
			}
			failures++;
		} else if (res != wdns_res_success) {
			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " res=%s", wdns_res_to_str(res));
		} else if (name.len != cur->expected_len || memcmp(name.data, cur->expected, name.len)) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));

			if (name.len != cur->expected_len) {
				ubuf_add_fmt(u, " len %d != %d",
						name.len, cur->expected_len);
			}

			ubuf_add_fmt(u, " res=%s",
					wdns_res_to_str(res));

			ubuf_add_cstr(u, " value=");
			escape(u, name.data, name.len);
			ubuf_add_cstr(u, " != ");
			escape(u, cur->expected, cur->expected_len);

			failures++;
		} else {
			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " res=%s",
					wdns_res_to_str(res));

			if (res == wdns_res_success) {
				ubuf_add_cstr(u, " value=");
				escape(u, name.data, name.len);
			}
		}

		fprintf (stderr, "%s\n", ubuf_cstr(u));
		if (name.data != NULL) {
			free(name.data);
			name.data = NULL;
		}
	}

	ubuf_destroy(&u);
	return failures;
}

int main (void)
{
	int ret = 0;

	ret |= check(test_str_to_name(), "test_str_to_name", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
