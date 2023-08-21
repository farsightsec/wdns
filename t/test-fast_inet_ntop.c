/*
 *
 * This test code was copied from BIND9 v9_10 and then extended.
 *
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "test-common.h"

#include "libmy/fast_inet_ntop.h"
#include "libmy/fast_inet_ntop.c"

#include <arpa/inet.h>

#define NAME "test-fast_inet_ntop"

static size_t
test_fast_inet_ntop(void) {
	char buf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	char rbuf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	size_t failures = 0;
	size_t i;
	unsigned char abuf[16];
	struct {
		int  family;
		const char * address;
	} testdata[] = {
		{ AF_INET, "0.0.0.0" },
		{ AF_INET, "0.1.0.0" },
		{ AF_INET, "0.0.2.0" },
		{ AF_INET, "0.0.0.3" },
		{ AF_INET, "1.2.3.4" },
		{ AF_INET, "98.51.100.1" },
		{ AF_INET, "255.255.255.255" },
		{ AF_INET6, "::" },
		{ AF_INET6, "::1.2.3.4" },
		{ AF_INET6, "::ffff:1.2.3.4" },
		{ AF_INET6, "2001:db8::" },
		{ AF_INET6, "2001:db8::ffff" },
		{ AF_INET6, "fedc:ba98:7654:3210:fedc:ba98:7654:3210" },
		{ AF_INET6, "1080::8:800:200c:417a" },
		{ AF_INET6, "::13.1.68.3" },
		{ AF_INET6, "::ffff:129.144.52.38" },
		{ AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
	};

	for (i = 0; i < sizeof(testdata)/sizeof(testdata[0]); i++) {

		/* not testing inet_pton() */
		inet_pton(testdata[i].family, testdata[i].address, abuf);

		fast_inet_ntop(testdata[i].family, abuf, buf, sizeof(buf));
		if (strcmp(buf, testdata[i].address) == 0) {
			fprintf(stderr, "PASS: fast_inet_ntop: %s = %s\n", buf, testdata[i].address);
		} else {
			fprintf(stderr, "FAIL: fast_inet_ntop: %s != %s\n", buf, testdata[i].address);
			failures++;
		}

		/* this is redundant */
		inet_ntop(testdata[i].family, abuf, rbuf, sizeof(rbuf));
		if (strcmp(buf, rbuf) == 0) {
			fprintf(stderr, "PASS: fast_inet_ntop %s = inet_ntop %s\n", buf, rbuf);
		} else {
			fprintf(stderr, "FAIL: fast_inet_ntop %s != inet_ntop %s\n", buf, rbuf);
			failures++;
		}
	}

	return(failures);
}

int main (void) {
	int ret = 0;

	ret |= check(test_fast_inet_ntop(), "test_fast_inet_ntop", NAME);

	if (ret)
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}
