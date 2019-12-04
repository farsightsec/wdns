#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>


void
escape(ubuf *u, const uint8_t *a, size_t len)
{
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

int
check(size_t ret, const char *s, const char *cname)
{
	if (ret == 0)
		fprintf(stderr, "%s : PASS: %s\n", cname, s);
	else
		fprintf(stderr, "%s : FAIL: %s (%zd failures)\n", cname, s, ret);
	return (ret);
}
