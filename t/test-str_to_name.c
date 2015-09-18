#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-str_to_name"

typedef wdns_res (*fp)(char*, wdns_name_t*);

struct test {
	char * input;
	fp func;
	const uint8_t *expected;
	size_t expected_len;
	wdns_res expected_res;
};

struct test tdata[] = {
	{ "fsi.io", (fp)wdns_str_to_name, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success},
	{ "FsI.io", (fp)wdns_str_to_name_case, (const uint8_t*)"\x03""FsI\x02io\x00", 8, wdns_res_success},
	{ 0 }
};

static void
escape(ubuf *u, const uint8_t * a, size_t len) {
	size_t n;
	bool last_hex = false;

	ubuf_add_cstr(u, "\"");
	for (n = 0; n < len; n++) {
		if (a[n] == '"') {
			ubuf_add_cstr(u, "\\\"");
			last_hex = false;
		} else if (a[n] == '\\') {
			ubuf_add_cstr(u, "\\\\");
			last_hex = false;
		} else if (a[n] >= ' ' && a[n] <= '~') {
			if (last_hex && isxdigit(a[n])) {
				ubuf_add_cstr(u, "\"\"");
			}
			ubuf_append(u, a+n, 1);
			last_hex = false;
		} else {
			ubuf_add_fmt(u, "\\x%02x", a[n]);
			last_hex = true;
		}
	}
	ubuf_add_cstr(u, "\"");
}

static size_t
test_str_to_name(void) {
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

static int
check(size_t ret, const char *s)
{
        if (ret == 0)
                fprintf(stderr, NAME ": PASS: %s\n", s);
        else
                fprintf(stderr, NAME ": FAIL: %s (%" PRIu64 " failures)\n", s, ret);
        return (ret);
}

int main (int argc, char **argv) {
	int ret = 0;

	ret |= check(test_str_to_name(), "test-str_to_name");

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
