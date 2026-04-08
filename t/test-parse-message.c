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
 *
 * Test for incomplete DNS records in wire format (via wdns_parse_message).
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-parse-message"

struct wire_test {
	const char *description;
	const void *rdata;
	size_t rdata_len;
	uint16_t rrtype;
	uint16_t rrclass;
	wdns_res expected_res;
};

static size_t
test_wire_format_rdata(void)
{
	ubuf *u;
	size_t failures = 0;

	const uint8_t header[] = {
		0, 0,		/* id */
		0x80, 0,	/* QR bit, rcode 0 (NOERROR) */
		0, 1,		/* QDCOUNT: 1 */
		0, 1, 		/* ANCOUNT: 1 */
		0, 0,		/* NSCOUNT: 0 */
		0, 0,		/* ARCOUNT: 0 */
	};
	const uint8_t dname[] = "\x07""example\x03""com\x00";

	struct wire_test tests[] = {
		/*
		 * SOA record with all required fields (valid)
		 */
		{
			.description = "SOA with all fields (valid)",
			.rrtype = WDNS_TYPE_SOA,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x02" "ns" "\x07" "example" "\x03" "com" "\x00"
				"\x05" "admin" "\x07" "example" "\x03" "com" "\x00"
				"\x00\x00\x07\xe8"  /* serial 2024 */
				"\x00\x00\x0e\x10"  /* refresh 3600 */
				"\x00\x00\x07\x08"  /* retry 1800 */
				"\x00\x09\x3a\x80"  /* expire 604800 */
				"\x00\x00\x0e\x10", /* minimum 3600 */
			.rdata_len = 35 + 20,
			.expected_res = wdns_res_success,
		},

		/*
		 * SOA record with only mname and rname (missing serial, refresh, retry, expire, minimum)
		 */
		{
			.description = "SOA with only mname and rname",
			.rrtype = WDNS_TYPE_SOA,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "\x02" "ns" "\x07" "example" "\x03" "com" "\x00"
				 "\x05" "admin" "\x07" "example" "\x03" "com" "\x00",
			.rdata_len = 35,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * SOA record with only mname, rname, and serial (missing refresh, retry, expire, minimum)
		 */
		{
			.description = "SOA with mname, rname, serial only",
			.rrtype = WDNS_TYPE_SOA,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x02" "ns" "\x07" "example" "\x03" "com" "\x00"
				"\x05" "admin" "\x07" "example" "\x03" "com" "\x00"
				"\x00\x00\x07\xe8",  /* serial only */
			.rdata_len = 39,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * MX record with preference and exchange (valid)
		 */
		{
			.description = "MX with preference and exchange (valid)",
			.rrtype = WDNS_TYPE_MX,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x00\x0a"  /* preference 10 */
				"\x04" "mail" "\x07" "example" "\x03" "com" "\x00",
			.rdata_len = 20,
			.expected_res = wdns_res_success,
		},

		/*
		 * MX record with only preference (missing exchange)
		 */
		{
			.description = "MX with only preference",
			.rrtype = WDNS_TYPE_MX,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "\x00\x0a",  /* preference=10 */
			.rdata_len = 2,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * MX record with no data
		 */
		{
			.description = "MX with no data",
			.rrtype = WDNS_TYPE_MX,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "",
			.rdata_len = 0,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * SRV record with all fields (valid)
		 */
		{
			.description = "SRV with all fields (valid)",
			.rrtype = WDNS_TYPE_SRV,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x00\x0a"  /* priority 10 */
				"\x00\x14"  /* weight 20 */
				"\x00\x50"  /* port 80 */
				"\x03" "srv" "\x07" "example" "\x03" "com" "\x00",
			.rdata_len = 23,
			.expected_res = wdns_res_success,
		},

		/*
		 * SRV record with only priority and weight (missing port and target)
		 */
		{
			.description = "SRV with only priority and weight",
			.rrtype = WDNS_TYPE_SRV,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "\x00\x0a\x00\x14",  /* priority=10, weight=20 */
			.rdata_len = 4,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * SRV record with only priority (missing weight, port, target)
		 */
		{
			.description = "SRV with only priority",
			.rrtype = WDNS_TYPE_SRV,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "\x00\x0a",  /* priority 10 */
			.rdata_len = 2,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * CAA record with flags, tag, and value (valid)
		 */
		{
			.description = "CAA with flags, tag, and value (valid)",
			.rrtype = WDNS_TYPE_CAA,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x00"  /* flags */
				"\x05" "issue"  /* tag length + value */
				"\x0d" "letsencrypt.org",  /* value length + value */
			.rdata_len = 23,
			.expected_res = wdns_res_success,
		},

		/*
		 * CAA record with only flags (missing tag and value)
		 */
		{
			.description = "CAA with only flags",
			.rrtype = WDNS_TYPE_CAA,
			.rrclass = WDNS_CLASS_IN,
			.rdata = "\x00",  /* flags=0 */
			.rdata_len = 1,
			.expected_res = wdns_res_parse_error,
		},

		/*
		 * CAA record with flags and tag (missing value)
		 */
		{
			.description = "CAA with flags and tag only",
			.rrtype = WDNS_TYPE_CAA,
			.rrclass = WDNS_CLASS_IN,
			.rdata =
				"\x00"  /* flags */
				"\x05" "issue",  /* tag only */
			.rdata_len = 7,
			.expected_res = wdns_res_parse_error,
		},

		{ .description = NULL }
	};

	u = ubuf_init(512);

	for (size_t i = 0; tests[i].description != NULL; i++) {
		const struct wire_test *test = &tests[i];
		ubuf *umsg;
		const uint8_t *msg;
		size_t msg_len;
		wdns_message_t m;
		wdns_res res;
		uint16_t rrtype, rrclass, rdlen;
		uint32_t rrttl = htonl(3600);

		umsg = ubuf_init(512);

		/* Build DNS message with test record */
		ubuf_append(umsg, header, sizeof(header));

		/* Question Section */
		ubuf_append(umsg, dname, sizeof(dname) - 1);  /* -1 for compiler-added null terminator */
		rrtype = htons(test->rrtype);
		rrclass = htons(test->rrclass);
		ubuf_append(umsg, (uint8_t *)&rrtype, 2);  /* Type (2 bytes) */
		ubuf_append(umsg, (uint8_t *)&rrclass, 2); /* Class (2 bytes) */

		/* Answer Section */
		ubuf_append(umsg, dname, sizeof(dname) - 1);  /* -1 for compiler-added null terminator */
		ubuf_append(umsg, (uint8_t *)&rrtype, 2);  /* Type (2 bytes) */
		ubuf_append(umsg, (uint8_t *)&rrclass, 2); /* Class (2 bytes) */
		ubuf_append(umsg, (uint8_t *)&rrttl, 4);   /* TTL (4 bytes) */
		rdlen = htons(test->rdata_len);
		ubuf_append(umsg, (uint8_t *)&rdlen, 2);   /* RDLEN (2 bytes) */
		ubuf_append(umsg, test->rdata, test->rdata_len); /* RDATA */

		msg = ubuf_data(umsg);
		msg_len = ubuf_size(umsg);

		res = wdns_parse_message(&m, msg, msg_len);

		ubuf_reset(u);
		if (res == test->expected_res) {
			ubuf_add_fmt(u, "PASS [WIRE]: %s", test->description);
		} else {
			ubuf_add_fmt(u, "FAIL [WIRE]: %s (got %s, expected %s)",
				test->description,
				wdns_res_to_str(res),
				wdns_res_to_str(test->expected_res));
			failures++;
		}

		fprintf(stderr, "%s\n", ubuf_cstr(u));

		if (res == wdns_res_success) {
			wdns_clear_message(&m);
		}
		ubuf_destroy(&umsg);
	}

	ubuf_destroy(&u);
	return failures;
}

int main(void)
{
	int ret = 0;

	ret |= check(test_wire_format_rdata(),
		"test_wire_format_rdata", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
