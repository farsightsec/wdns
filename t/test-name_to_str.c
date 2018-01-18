#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-name_to_str"

struct test {
	const void *input;
	size_t ilen;
	const char *expected;
	const char *expected_lcase;
	const char *expected_rev;
	size_t skip_len;
};

struct test tdata[] = {
	{
		.input = "\x03" "fsi" "\x02" "io",
		.ilen = 1 + 3 + 1 + 2 + 1,
		.expected = "fsi.io.",
		.expected_lcase = "fsi.io.",
		.expected_rev = "io.fsi.",
		.skip_len = 1 + 3 + 1 + 2 + 1,
	},
	{
		.input = "\x04" "abcd" "\x03" "fsi" "\x02" "IO",
		.ilen = 1 + 4 + 1 + 3 + 1 + 2 + 1,
		.expected = "abcd.fsi.IO.",
		.expected_lcase = "abcd.fsi.io.",
		.expected_rev = "IO.fsi.abcd.",
		.skip_len = 1 + 4 + 1 + 3 + 1 + 2 + 1,
	},
	{
		.input = "\x05" "Mixed" "\x03" "fsi" "\x02" "IO",
		.ilen = 1 + 5 + 1 + 3 + 1 + 2 + 1,
		.expected = "Mixed.fsi.IO.",
		.expected_lcase = "mixed.fsi.io.",
		.expected_rev = "IO.fsi.Mixed.",
		.skip_len = 1 + 5 + 1 + 3 + 1 + 2 + 1,
	},
	{
		.input = "\x07" "testing" "\x08" "trailing" "\x04" "data" "\x03" "fsi" "\x02" "io" "\x00" "\x04" "abcd",
		.ilen = 1 + 7 + 1 + 8 + 1 + 4 + 1 + 3 + 1 + 2 + 1     + 1 + 4 + 1,
		.expected = "testing.trailing.data.fsi.io.",
		.expected_lcase = "testing.trailing.data.fsi.io.",
//		.expected_rev = "io.fsi.data.trailing.testing.",
		.expected_rev = ".",
		.skip_len = 1 + 7 + 1 + 8 + 1 + 4 + 1 + 3 + 1 + 2 + 1,
	},
	{
		0
	}
};


static size_t
test_name_to_str(void)
{
	char dstr[1024];
	ubuf *u;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);

	for(cur = tdata; cur->input != NULL; cur++) {
		wdns_name_t name;
		wdns_res res;
		int err = 0;

		ubuf_reset(u);
		memset(&name, 0, sizeof(name));
		memset(dstr, 0, sizeof(dstr));

		wdns_domain_to_str(cur->input, cur->ilen, dstr);

		if (strcmp(dstr, cur->expected)) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " name %s != %s", dstr, cur->expected);
			err = 1;
		}

		if (!err) {
			name.data = malloc(cur->ilen);
			memcpy(name.data, cur->input, cur->ilen);
			name.len = cur->ilen;
			wdns_downcase_name(&name);

			memset(dstr, 0, sizeof(dstr));
			wdns_domain_to_str(name.data, name.len, dstr);

			if (strcmp(dstr, cur->expected_lcase)) {
				ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
				escape(u, (uint8_t*)cur->input, strlen(cur->input));
				ubuf_add_fmt(u, " lowercase name %s != %s", dstr, cur->expected_lcase);
				err = 1;
			}

		}

		if (!err) {
			memset(name.data, 0, name.len);

			if (wdns_reverse_name(cur->input, cur->ilen, name.data) != wdns_res_success) {
				ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
				escape(u, (uint8_t*)cur->input, strlen(cur->input));
				ubuf_add_fmt(u, " reverse name failure");
				err = 1;
			} else {
				memset(dstr, 0, sizeof(dstr));
				wdns_domain_to_str(name.data, name.len, dstr);

				if (strcmp(dstr, cur->expected_rev)) {
					ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
					escape(u, (uint8_t*)cur->input, strlen(cur->input));
					ubuf_add_fmt(u, " reverse name %s != %s", dstr, cur->expected_rev);
					err = 1;
				}

			}

		}

		if (!err) {
			const u_int8_t *sptr = cur->input;

			res = wdns_skip_name(&sptr, (((const uint8_t *)cur->input) + cur->ilen));

			if (res != cur->skip_len) {
				ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
				escape(u, (uint8_t*)cur->input, strlen(cur->input));
				ubuf_add_fmt(u, " skip len %zu != %zu", res, cur->skip_len);
				err = 1;
			}

		}

		if (!err) {
			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, cur->ilen);
		} else {
			failures++;
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

int main (int argc, char **argv)
{
	int ret = 0;

	ret |= check(test_name_to_str(), "test-name_to_str", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
