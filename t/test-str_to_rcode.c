/*
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

#define NAME "test-str_to_rcode"

static struct u16str {
	uint16_t u16;
	const char *str;
} rcodes[] = {
	{ WDNS_R_BADVERS, "BADVERS" },
	{ WDNS_R_FORMERR, "FORMERR" },
	{ WDNS_R_NOERROR, "NOERROR" },
	{ WDNS_R_NOTAUTH, "NOTAUTH" },
	{ WDNS_R_NOTIMP, "NOTIMP" },
	{ WDNS_R_NOTZONE, "NOTZONE" },
	{ WDNS_R_NXDOMAIN, "NXDOMAIN" },
	{ WDNS_R_NXRRSET, "NXRRSET" },
	{ WDNS_R_REFUSED, "REFUSED" },
	{ WDNS_R_SERVFAIL, "SERVFAIL" },
	{ WDNS_R_YXDOMAIN, "YXDOMAIN" },
	{ WDNS_R_YXRRSET, "YXRRSET" },
};

#define num_rcodes (sizeof(rcodes) / sizeof(struct u16str))

static size_t
test_str_to_rcode(void)
{
	size_t n;
	size_t failures = 0;

	for (n = 0; n < num_rcodes; n++) {
		uint16_t rcode;
		wdns_res res;
		res = wdns_str_to_rcode(rcodes[n].str, &rcode);
		if (res != wdns_res_success) {
			fprintf (stderr, "FAIL: %s res=%s\n", rcodes[n].str, wdns_res_to_str(res));
		} else if (rcode != rcodes[n].u16) {
			fprintf (stderr, "FAIL: %s %d != %d\n", rcodes[n].str, rcode, rcodes[n].u16);
			failures++;
		} else {
			fprintf (stderr, "PASS: %s = %d\n", rcodes[n].str, rcode);
		}
	}

	return failures;
}

int main (void)
{
	int ret = 0;

	ret |= check(test_str_to_rcode(), "test_rcode", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
