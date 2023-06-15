/*
 * Copyright (c) 2022 DomainTools LLC
 * Copyright (c) 2015-2018, 2021 by Farsight Security, Inc.
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

#define NAME "test-str_to_rdata"

struct test {
	char * input;
	uint16_t rrtype;
	uint16_t rrclass;
	const void *expected;
	size_t expected_len;
	wdns_res expected_res;
};

static const struct test tdata[] = {
	{
		.rrtype = WDNS_TYPE_TLSA,
		.rrclass = WDNS_CLASS_IN,
		.input =
			"0 0 1 "
			"d2abde240d7cd3ee6b4b28c54df034b9"
			"7983a1d16e8a410e4561cb106618e971",
		.expected =
			"\x00" "\x00" "\x01"
			"\xd2\xab\xde\x24\x0d\x7c\xd3\xee\x6b\x4b\x28\xc5\x4d\xf0\x34\xb9"
			"\x79\x83\xa1\xd1\x6e\x8a\x41\x0e\x45\x61\xcb\x10\x66\x18\xe9\x71",
		.expected_len = 1 + 1 + 1 + 32,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_DNSKEY,
		.rrclass = WDNS_CLASS_IN,
		.input =
			"256 3 5 "
			"AQPSKmynfzW4kyBv015MUG2DeIQ3 "
			"Cbl+BBZH4b/0PY1kxkmvHjcZc8no "
			"kfzj31GajIQKY+5CptLr3buXA10h "
			"WqTkF7H6RfoRqXQeogmMHfpftf6z "
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL "
			"742iU/TpPSEDhm2SNKLijfUppn1U "
			"aNvv4w==",
		.expected =
			"\x01\x00" "\x03" "\x05"
			"\x01\x03\xd2\x2a\x6c\xa7\x7f\x35\xb8\x93\x20\x6f\xd3\x5e\x4c\x50"
			"\x6d\x83\x78\x84\x37\x09\xb9\x7e\x04\x16\x47\xe1\xbf\xf4\x3d\x8d"
			"\x64\xc6\x49\xaf\x1e\x37\x19\x73\xc9\xe8\x91\xfc\xe3\xdf\x51\x9a"
			"\x8c\x84\x0a\x63\xee\x42\xa6\xd2\xeb\xdd\xbb\x97\x03\x5d\x21\x5a"
			"\xa4\xe4\x17\xb1\xfa\x45\xfa\x11\xa9\x74\x1e\xa2\x09\x8c\x1d\xfa"
			"\x5f\xb5\xfe\xb3\x32\xfd\x4b\xc8\x15\x20\x89\xae\xf3\x6b\xa6\x44"
			"\xcc\xe2\x41\x3b\x3b\x72\xbe\x18\xcb\xef\x8d\xa2\x53\xf4\xe9\x3d"
			"\x21\x03\x86\x6d\x92\x34\xa2\xe2\x8d\xf5\x29\xa6\x7d\x54\x68\xdb"
			"\xef\xe3",
		.expected_len = 2 + 1 + 1 + 130,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_CDNSKEY,
		.rrclass = WDNS_CLASS_IN,
		.input =
			"256 3 5 "
			"AQPSKmynfzW4kyBv015MUG2DeIQ3 "
			"Cbl+BBZH4b/0PY1kxkmvHjcZc8no "
			"kfzj31GajIQKY+5CptLr3buXA10h "
			"WqTkF7H6RfoRqXQeogmMHfpftf6z "
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL "
			"742iU/TpPSEDhm2SNKLijfUppn1U "
			"aNvv4w==",
		.expected =
			"\x01\x00" "\x03" "\x05"
			"\x01\x03\xd2\x2a\x6c\xa7\x7f\x35\xb8\x93\x20\x6f\xd3\x5e\x4c\x50"
			"\x6d\x83\x78\x84\x37\x09\xb9\x7e\x04\x16\x47\xe1\xbf\xf4\x3d\x8d"
			"\x64\xc6\x49\xaf\x1e\x37\x19\x73\xc9\xe8\x91\xfc\xe3\xdf\x51\x9a"
			"\x8c\x84\x0a\x63\xee\x42\xa6\xd2\xeb\xdd\xbb\x97\x03\x5d\x21\x5a"
			"\xa4\xe4\x17\xb1\xfa\x45\xfa\x11\xa9\x74\x1e\xa2\x09\x8c\x1d\xfa"
			"\x5f\xb5\xfe\xb3\x32\xfd\x4b\xc8\x15\x20\x89\xae\xf3\x6b\xa6\x44"
			"\xcc\xe2\x41\x3b\x3b\x72\xbe\x18\xcb\xef\x8d\xa2\x53\xf4\xe9\x3d"
			"\x21\x03\x86\x6d\x92\x34\xa2\xe2\x8d\xf5\x29\xa6\x7d\x54\x68\xdb"
			"\xef\xe3",
		.expected_len = 2 + 1 + 1 + 130,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_DS,
		.rrclass = WDNS_CLASS_IN,
		.input = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
		.expected =
			"\xec\x45" "\x05" "\x01"
			"\x2b\xb1\x83\xaf\x5f\x22\x58\x81\x79\xa5\x3b\x0a\x98\x63\x1f\xad\x1a\x29\x21\x18",
		.expected_len = 2 + 1 + 1 + 20,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_CDS,
		.rrclass = WDNS_CLASS_IN,
		.input = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
		.expected =
			"\xec\x45" "\x05" "\x01"
			"\x2b\xb1\x83\xaf\x5f\x22\x58\x81\x79\xa5\x3b\x0a\x98\x63\x1f\xad\x1a\x29\x21\x18",
		.expected_len = 2 + 1 + 1 + 20,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_OPENPGPKEY,
		.rrclass = WDNS_CLASS_IN,
		.input = "AQIDBAUGBwg=",
		.expected = "\x01\x02\x03\x04\x05\x06\x07\x08",
		.expected_len = 8,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_CSYNC,
		.rrclass = WDNS_CLASS_IN,
		.input = "66 3 A NS AAAA",
		.expected =
			"\x00\x00\x00\x42"
			"\x00\x03"
			"\x00\x04\x60\x00\x00\x08",
		.expected_len = 4 + 2 + 6,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_EUI48,
		.rrclass = WDNS_CLASS_IN,
		.input = "AB-CD-EF-01-02-03",
		.expected = "\xAB\xCD\xEF\x01\x02\x03",
		.expected_len = 6,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_EUI64,
		.rrclass = WDNS_CLASS_IN,
		.input = "AB-CD-EF-01-02-03-04-05",
		.expected = "\xAB\xCD\xEF\x01\x02\x03\x04\x05",
		.expected_len = 8,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.input = "10 1 \"ftp://ftp1.example.com/public\"",
		.expected =
			"\x00\x0a"
			"\x00\x01"
			"ftp://ftp1.example.com/public",
		.expected_len = 2 + 2 + 29,
		.expected_res = wdns_res_success,
	},

	{
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.input = "10 1 \"ftp://ftp1.ex\\097mple.com/public\"",
		.expected =
			"\x00\x0a"
			"\x00\x01"
			"ftp://ftp1.example.com/public",
		.expected_len = 2 + 2 + 29,
		.expected_res = wdns_res_success,
	},

	{ "fsi.io.", WDNS_TYPE_CNAME, WDNS_CLASS_IN, "\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "fsi.io", WDNS_TYPE_CNAME, WDNS_CLASS_IN, "\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "fsi.io..", WDNS_TYPE_CNAME, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ ".", WDNS_TYPE_CNAME, WDNS_CLASS_IN, "\x00", 1, wdns_res_success},
	{ "", WDNS_TYPE_CNAME, WDNS_CLASS_IN, "", 0, wdns_res_success},
	{ "\"hardware\" \"os\"", WDNS_TYPE_HINFO, WDNS_CLASS_IN, "\x08hardware\x02os", 12, wdns_res_success},
	{ "hardware os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, "\x08hardware\x02os", 12, wdns_res_success},
	{ "hardware\\\" os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, "\x09hardware\"\x02os", 13, wdns_res_success},
	{ "hardware\\032 os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, "\x09hardware \x02os", 13, wdns_res_success},
	{ "hardware\\03a os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware\\256 os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware\\n os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware os\\", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware os\x01", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi.io. farsightsecurity.com", WDNS_TYPE_MINFO, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x10""farsightsecurity\x03""com\x00", 30, wdns_res_success },
	{ "fsi.io.", WDNS_TYPE_MINFO, WDNS_CLASS_IN, "\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "", WDNS_TYPE_MINFO, WDNS_CLASS_IN, "", 0, wdns_res_success },
	{ "5 mail.fsi.io.", WDNS_TYPE_MX, WDNS_CLASS_IN, "\x00\x05\x04mail\x03""fsi\x02io\x00", 15, wdns_res_success },
	{ "foo mail.fsi.io.", WDNS_TYPE_MX, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "5", WDNS_TYPE_MX, WDNS_CLASS_IN, "\x00\x05", 2, wdns_res_success },
	{ "", WDNS_TYPE_MX, WDNS_CLASS_IN, 0, 0, wdns_res_success },
	{ "", WDNS_TYPE_NULL, WDNS_CLASS_IN, "", 0, wdns_res_success},
	{ "05", WDNS_TYPE_NULL, WDNS_CLASS_IN, "\x05", 1, wdns_res_success},
	{ "FF05", WDNS_TYPE_NULL, WDNS_CLASS_IN, "\xff\x05", 2, wdns_res_success},
	{ "ABFF05", WDNS_TYPE_NULL, WDNS_CLASS_IN, "\xab\xff\x05", 3, wdns_res_success},
	{ "abff05", WDNS_TYPE_NULL, WDNS_CLASS_IN, "\xab\xff\x05", 3, wdns_res_success},
	{ "abcdff05", WDNS_TYPE_NULL, WDNS_CLASS_IN, "\xab\xcd\xff\x05", 4, wdns_res_success},
	{ "5", WDNS_TYPE_NULL, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "12345", WDNS_TYPE_NULL, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "fsi.io. root.fsi.io. 65536 1024 127 33554432 0", WDNS_TYPE_SOA, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x04root\x03""fsi\x02io\x00\x00\x01\x00\x00\x00\x00\x04\x00\x00\x00\x00\x7f\x02\x00\x00\x00\x00\x00\x00\x00", 41, wdns_res_success },
	{ "", WDNS_TYPE_TXT, WDNS_CLASS_IN, "", 0, wdns_res_success},
	{ "txt", WDNS_TYPE_TXT, WDNS_CLASS_IN, "\x03txt", 4, wdns_res_success},
	{ "txt rec", WDNS_TYPE_TXT, WDNS_CLASS_IN, "\x03txt\x03rec", 8, wdns_res_success},
	{ "txt \"record\"", WDNS_TYPE_TXT, WDNS_CLASS_IN, "\x03txt\x06record", 11, wdns_res_success},
	{ "txt \"record\" three", WDNS_TYPE_TXT, WDNS_CLASS_IN, "\x03txt\x06record\x05three", 17, wdns_res_success},
	{ "txt \"record\" three\\", WDNS_TYPE_TXT, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0.1", WDNS_TYPE_A, WDNS_CLASS_IN, "\x7f\x00\x00\x01", 4, wdns_res_success},
	{ "127.0.0.256", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0.0.1", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "::1", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "305419896 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, "\x12\x34\x56\x78\x7f\x00\xde\xad\xbe\xef\x00", 11, wdns_res_success },
	{ "4294967297 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "-1 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "128 2000::dead:beef fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, "\x80\x03""fsi\x02io\x00", 9, wdns_res_success },
	{ "120 2000::dead:beef fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, "\x78\xef\x03""fsi\x02io\x00", 10, wdns_res_success },
	{ "2000::dead:beef fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "0 ::", WDNS_TYPE_A6, WDNS_CLASS_IN, "\x00""\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 17, wdns_res_success},
	{ "0 :: fsi.io", WDNS_TYPE_A6, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "::", WDNS_TYPE_AAAA, WDNS_CLASS_IN, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, wdns_res_success},
	{ "1234:4567::abcd:ef01", WDNS_TYPE_AAAA, WDNS_CLASS_IN, "\x12\x34\x45\x67\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd\xef\x01", 16, wdns_res_success},
	{ "::abcd:ef01", WDNS_TYPE_AAAA, WDNS_CLASS_IN, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd\xef\x01", 16, wdns_res_success },
	{ "", WDNS_TYPE_AAAA, WDNS_CLASS_IN, "", 0, wdns_res_success},
	{ "127.0.0.1", WDNS_TYPE_AAAA, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi.io", WDNS_TYPE_AAAA, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "65535 64 01 ZGVhZGJlZWY=", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, "\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWY==", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, "\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWY", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, "\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWZz", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, "\xff\xff@\x01""deadbeefs", 13, wdns_res_success},
	{ "fsi.io A NS MX", WDNS_TYPE_NSEC, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x00\x02\x60\x01", 12, wdns_res_success},
	{ "fsi.io", WDNS_TYPE_NSEC, WDNS_CLASS_IN, "\x03""fsi\x02io\x00", 8, wdns_res_success},
	/* Test for not outputing an empty bitmap and test parsing a TYPE### RRtype*/
	{ "fsi.io URI CAA TYPE258", WDNS_TYPE_NSEC, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x01\x01\xe0", 11, wdns_res_success},
	{ "fsi.io A NS MD MF CNAME SOA MB MG MR WKS PTR HINFO MINFO MX TXT RP AFSDB URI CAA", WDNS_TYPE_NSEC, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x00\x03\x7f\xdf\xe0\x01\x01\xc0", 16, wdns_res_success},
	/* The next test case uses the same rrtypes as the previous, but
	 * sorted by name in order to shuffle them by value.  */
	{ "fsi.io A AFSDB CAA CNAME HINFO MB MD MF MG MINFO MR MX NS PTR RP SOA TXT URI WKS", WDNS_TYPE_NSEC, WDNS_CLASS_IN, "\x03""fsi\x02io\x00\x00\x03\x7f\xdf\xe0\x01\x01\xc0", 16, wdns_res_success},
	{ "fsi.io A NS MX FAKE", WDNS_TYPE_NSEC, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 -", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, "\x01\x02\x00\x03\x00", 5, wdns_res_success},
	{ "1 2 3 deadbeef", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, "\x01\x02\x00\x03\x04\xde\xad\xbe\xef", 9, wdns_res_success},
	{ "1 2 3 deadbeeff", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 deadbeef-", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 gg", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 --", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, "\x01\x02\x00\x03", 4, wdns_res_success },
	{ "1 1 10 7225a239d4230bba7be2 O4K23SKVI7PTGVR5LRITC8IDIQ6KJVA0 NS DS RRSIG", WDNS_TYPE_NSEC3, WDNS_CLASS_IN, "\x01\x01\x00\x0a\x0ar%\xa2""9\xd4#\x0b\xba{\xe2\x14\xc1(!\xf2\x9f\x91\xf3\xd8\x7f""e\xae\xe5\xd6\"M\x96\x8dI\xfd@\x00\x06 \x00\x00\x00\x00\x12", 44, wdns_res_success },
	{ "1 1 0 - 00 A SOA", WDNS_TYPE_NSEC3, WDNS_CLASS_IN, "\x01\x01\x00\x00\x00\x01\x00\x00\x01\x42", 10, wdns_res_success },
	{ "NSEC 5 5 7200 1442949945 1440354345 34572 5.in-addr.arpa. aTPqHqvtDsdyY6acy5BzbmjzJcdNWeFW2laTYY/+NJsMAedSryvDJKkA evVh4Fv4G+o9Ts3XKhYUihW2qXp7bbhHmlIvSY3qX67/Ti9DzRPymirt m5ffESFO7+4H2QFd5xIpoJH/WQysNWzCyLt+JeguH4/7PU5C9K30cqqd vJk=", WDNS_TYPE_RRSIG, WDNS_CLASS_IN, "\x00/\x05\x05\x00\x00\x1c V\x01\xab""9U\xda\x10)\x87\x0c\x01""5\x07in-addr\x04""arpa\x00i3\xea\x1e\xab\xed\x0e\xc7rc\xa6\x9c\xcb\x90snh\xf3%\xc7MY\xe1V\xdaV\x93""a\x8f\xfe""4\x9b\x0c\x01\xe7R\xaf+\xc3$\xa9\x00z\xf5""a\xe0[\xf8\x1b\xea=N\xcd\xd7*\x16\x14\x8a\x15\xb6\xa9z{m\xb8G\x9aR/I\x8d\xea_\xae\xffN/C\xcd\x13\xf2\x9a*\xed\x9b\x97\xdf\x11!N\xef\xee\x07\xd9\x01]\xe7\x12)\xa0\x91\xffY\x0c\xac""5l\xc2\xc8\xbb~%\xe8.\x1f\x8f\xfb=NB\xf4\xad\xf4r\xaa\x9d\xbc\x99", 162, wdns_res_success },
	{ "NSEC3 10 3 172800 1443179274 1440584754 25427 go.id. TzGzKBNpQysYIEBHzCMub5PSg6H564xt2c/JYW6fCOyoUesDqECbJHDl 6pgyQaicCrsdSuqImSi1Ej63OEgJ1o5gKUQh0brq7i8oDZ343M57j9O7 hk7Hm+066r2dEKAD2c0SKeFTdOhjWk01Opkw+DW0SbhvKbsngII3e5mb y7+uSW3TH0OX/nOZMte8F1z98UyGKjRsInlXfc4nh2TknrwvGFgRZoS1 X2PWLkzVQSjGsfLS1/N01TYVGe0IyDWoY6csNQhnSS53Z1WAIZOuSoV5 oBBCQIQFDjknqT9/YkqQNCJso0xGcr2CyQHKcVduxYGgVarEABANrDQV DxpuEeaYGS7+eGJT+sznItOTQeSSYougSu6DsxVwYyTix/alO+KpUwzP 7YZBJIssnHYdqUvXQlcxpYtlhEYcISlcP5Ate/A2hoDR+KXo1+6ydBUy gmNTLRYVX7N+ajRnBIAhAoaGotpgzUe3uZIoiKi8FY/L4glE93mFCBqb +4mJ7O5rtWlnHy9jMlW9AIzoqfDmLoNaTUF1D6mdkVU5Gs+E0gST6Mln arJtIHttDLz/GZMOnd79+GKTdKUr5Ch4QP5LALys6WDWa2EdUg2ZWH5m hqU+5XQDMcOFyeyLsqudy4DkXk2rFMtGQlU0crzaKKyf+qSeMbXMda1F GU+kwrQvgtE=", WDNS_TYPE_RRSIG, WDNS_CLASS_IN, "\x00""2\x0a\x03\x00\x02\xa3\x00V\x05+\x0aU\xdd\x94""2cS\x02go\x02id\x00O1\xb3(\x13iC+\x18 @G\xcc#.o\x93\xd2\x83\xa1\xf9\xeb\x8cm\xd9\xcf\xc9""an\x9f\x08\xec\xa8Q\xeb\x03\xa8@\x9b$p\xe5\xea\x98""2A\xa8\x9c\x0a\xbb\x1dJ\xea\x88\x99(\xb5\x12>\xb7""8H\x09\xd6\x8e`)D!\xd1\xba\xea\xee/(\x0d\x9d\xf8\xdc\xce{\x8f\xd3\xbb\x86N\xc7\x9b\xed:\xea\xbd\x9d\x10\xa0\x03\xd9\xcd\x12)\xe1St\xe8""cZM5:\x99""0\xf8""5\xb4I\xb8o)\xbb'\x80\x82""7{\x99\x9b\xcb\xbf\xaeIm\xd3\x1f""C\x97\xfes\x99""2\xd7\xbc\x17\\\xfd\xf1L\x86*4l\"yW}\xce'\x87""d\xe4\x9e\xbc/\x18X\x11""f\x84\xb5_c\xd6.L\xd5""A(\xc6\xb1\xf2\xd2\xd7\xf3t\xd5""6\x15\x19\xed\x08\xc8""5\xa8""c\xa7,5\x08gI.wgU\x80!\x93\xaeJ\x85y\xa0\x10""B@\x84\x05\x0e""9'\xa9?\x7f""bJ\x90""4\"l\xa3LFr\xbd\x82\xc9\x01\xcaqWn\xc5\x81\xa0U\xaa\xc4\x00\x10\x0d\xac""4\x15\x0f\x1an\x11\xe6\x98\x19.\xfexbS\xfa\xcc\xe7\"\xd3\x93""A\xe4\x92""b\x8b\xa0J\xee\x83\xb3\x15pc$\xe2\xc7\xf6\xa5;\xe2\xa9S\x0c\xcf\xed\x86""A$\x8b,\x9cv\x1d\xa9K\xd7""BW1\xa5\x8b""e\x84""F\x1c!)\\?\x90-{\xf0""6\x86\x80\xd1\xf8\xa5\xe8\xd7\xee\xb2t\x15""2\x82""cS-\x16\x15_\xb3~j4g\x04\x80!\x02\x86\x86\xa2\xda`\xcdG\xb7\xb9\x92(\x88\xa8\xbc\x15\x8f\xcb\xe2\x09""D\xf7y\x85\x08\x1a\x9b\xfb\x89\x89\xec\xeek\xb5ig\x1f/c2U\xbd\x00\x8c\xe8\xa9\xf0\xe6.\x83ZMAu\x0f\xa9\x9d\x91U9\x1a\xcf\x84\xd2\x04\x93\xe8\xc9gj\xb2m {m\x0c\xbc\xff\x19\x93\x0e\x9d\xde\xfd\xf8""b\x93t\xa5+\xe4(x@\xfeK\x00\xbc\xac\xe9`\xd6ka\x1dR\x0d\x99X~f\x86\xa5>\xe5t\x03""1\xc3\x85\xc9\xec\x8b\xb2\xab\x9d\xcb\x80\xe4^M\xab\x14\xcb""FBU4r\xbc\xda(\xac\x9f\xfa\xa4\x9e""1\xb5\xccu\xad""E\x19O\xa4\xc2\xb4/\x82\xd1", 537, wdns_res_success },
	/* generic encodings */
	{ "\\# 24 d5 79 08 01 98 4e d2 96 9a 76 0c f6 09 8e a1 4a 84 65 16 9c aa 9c 48 07", 32769, WDNS_CLASS_IN, "\xd5\x79\x08\x01\x98\x4e\xd2\x96\x9a\x76\x0c\xf6\x09\x8e\xa1\x4a\x84\x65\x16\x9c\xaa\x9c\x48\x07", 24, wdns_res_success },

	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"h2\"",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x03"				/* length.. */
		    "\x02h2",				/* ..value */
		.expected_len = 10,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = QUOTE(1 . alpn="h2\128\000\""),
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x06"				/* length.. */
		    "\x05h2\x80\x00\"",			/* ..value */
		.expected_len = 13,
		.expected_res = wdns_res_success,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 Appendix A.1 */
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"part1,part2,part3\\\\,part4\\\\\\\\\"",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x19"				/* length.. */
		    "\x05part1\x05part2\x0cpart3,part4\\\\",	/* ..value */
		.expected_len = 32,
		.expected_res = wdns_res_success,
	},
// commented out because the current character-string parsing code of
// wdns does not allow arbitrary characters to be escaped, only '\', '"',
// and three-digit decimal sequences, so the "\," was being rejected.
//	{ /* draft-ietf-dnsop-svcb-https-08 Appendix A.1 */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . alpn=part1\\,\\p\\a\\r\\t2\\044part3\\092,part4\\092\\\\",
//		.expected = "\x00\x01"			/* priority */
//		    "\x00"				/* target */
//		    "\x00\x01"				/* alpn */
//		    "\x00\x19"				/* length.. */
//		    "\x05part1\x05part2\x0cpart3,part4\\\\",	/* ..value */
//		.expected_len = 32,
//		.expected_res = wdns_res_success,
//	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = QUOTE(1 . alpn="h2\\"),
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = QUOTE(1 . alpn="h2\,"),
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"h2",
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . unknown=value",
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     alpha-lc      = %x61-7A   ;  a-z
	     SvcParamKey   = 1*63(alpha-lc / DIGIT / "-")
	     15.3.1
	     The characters in the registered Name MUST be lower-case
	     alphanumeric or "-" */
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . under_score=value", /* underscore is invalid in SvcParamKey */
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     alpha-lc      = %x61-7A   ;  a-z
	     SvcParamKey   = 1*63(alpha-lc / DIGIT / "-")
	     15.3.1
	     The characters in the registered Name MUST be lower-case
	     alphanumeric or "-" */
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ALPN=\"h2,h3\"", /* Uppercase is invalid in SvcParamKey */
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . key65535=value",
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"h2,h3\"",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x06"				/* length */
		    "\x02h2"				/* ..value */
		    "\x02h3",				/* ..value */
		.expected_len = 13,
		.expected_res = wdns_res_success,
	},
// commented out since the wire format may represent these, so for wdns
// purposes, the code allows these invalid configurations unambiguously.
//	{ /* draft-ietf-dnsop-svcb-https-08 2.1
//	     SvcParams in presentation format MAY appear in any order, but keys
//	     MUST NOT be repeated. */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . alpn=\"h2,h3\" alpn=\"h2,h3\"",
//		.expected_res = wdns_res_parse_error,
//	},
//	{ /* Same as above test by use keyNUM for first use
//	     draft-ietf-dnsop-svcb-https-08 2.1
//	     SvcParams in presentation format MAY appear in any order, but keys
//	     MUST NOT be repeated. */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . key1=\"h2,h3\" alpn=\"h2,h3\"",
//		.expected_res = wdns_res_parse_error,
//	},
//	{ /* Same as above test by use keyNUM for second use
//	     draft-ietf-dnsop-svcb-https-08 2.1
//	     SvcParams in presentation format MAY appear in any order, but keys
//	     MUST NOT be repeated. */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . alpn=\"h2,h3\" key1=\"h2,h3\"",
//		.expected_res = wdns_res_parse_error,
//	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"h2,h3\" no-default-alpn",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x06"				/* length.. */
		    "\x02h2"				/* ..value */
		    "\x02h3"				/* ..value */
		    "\x00\x02\x00\x00",			/* no-default-alpn */
		.expected_len = 17,
		.expected_res = wdns_res_success,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 7.1.1
	     For "no-default-alpn", the presentation and wire format
	     values MUST be empty. */
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . alpn=\"h2,h3\" no-default-alpn=1",
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
//	{ /* draft-ietf-dnsop-svcb-https-08 7.1.1
//	     When "no-default-alpn" is specified in an RR, "alpn" must
//	     also be specified in order for the RR to be "self-consistent" */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . no-default-alpn",
//		.expected = "",
//		.expected_len = 0,
//		.expected_res = wdns_res_parse_error,
//	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . port=1111",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x03"				/* port */
		    "\x00\x02"				/* length.. */
		    "\x04W",				/* ..value */
		.expected_len = 9,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ipv4hint=192.168.0.1",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x04"				/* ipv4hint */
		    "\x00\x04"				/* length.. */
		    "\xc0\xa8\x00\x01",			/* ..value */
		.expected_len = 11,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ipv4hint=192.168.0.1,192.168.0.2",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x04"				/* ipv4hint */
		    "\x00\x08"				/* length.. */
		    "\xc0\xa8\x00\x01"			/* ..value */
		    "\xc0\xa8\x00\x02",			/* ..value */
		.expected_len = 15,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ipv6hint=2001:db8::1",
		.expected = "\x00\x01"			/* priority */
		    "\x00"     				/* target */
		    "\x00\x06"				/* ipv6hint */
		    "\x00\x10"				/* length.. */
		    "\x20\x01\x0d\xb8\x00\x00\x00\x00"	/* ..val */
		    "\x00\x00\x00\x00\x00\x00\x00\x01",	/* ..val */
		.expected_len = 23,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ech",
		.expected_res = wdns_res_parse_error,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . ech=abcdefghijkl",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x05"				/* ech */
		    "\x00\x09"				/* length.. */
		    "i\xb7\x1dy\xf8!\x8a""""9%",	/* ..value */
		.expected_len = 16,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . mandatory=alpn,port alpn=\"h2,h3\" no-default-alpn port=1111 ipv4hint=192.168.0.1,192.168.0.2 ipv6hint=2001:db8::1",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x00"				/* mandatory */
		    "\x00\x04"				/* length.. */
		    "\x00\x01\x00\x03"			/* ..val (alpn, port) */
		    "\x00\x01"				/* alpn */
		    "\x00\x06"				/* length.. */
		    "\x02h2"				/* ..value */
		    "\x02h3"				/* ..value */
		    "\x00\x02\x00\x00"			/* no-default-alpn */
		    "\x00\x03"				/* port */
		    "\x00\x02"				/* length.. */
		    "\x04W"				/* ..value */
		    "\x00\x04"				/* ipv4hint */
		    "\x00\x08"				/* length.. */
		    "\xc0\xa8\x00\x01"			/* ..value */
		    "\xc0\xa8\x00\x02"			/* ..value */
		    "\x00\x06"				/* ipv6hint */
		    "\x00\x10"				/* length.. */
		    "\x20\x01\x0d\xb8\x00\x00\x00\x00"	/* ..value */
		    "\x00\x00\x00\x00\x00\x00\x00\x01",
		.expected_len = 63,
		.expected_res = wdns_res_success,
	},
	{
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . key10=\"222\"",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target */
		    "\x00\x0a"				/* 10 */
		    "\x00\x03"				/* length.. */
		    "222",				/* ..value */
		.expected_len = 10,
		.expected_res = wdns_res_success,
	},
// commented out since the draft says it uses RFC1035 5.1.  The draft's
// ABNF summary doesn't match so wdns is not as restrictive.
//	{ /* draft-ietf-dnsop-svcb-https-08  2.1
//	     The SvcParamValue is parsed using the character-string decoding
//	     algorithm (Appendix A)  */
//		.rrtype = WDNS_TYPE_HTTPS,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "1 . key10=222\"",		/* Missing start quote */
//		.expected = "",
//		.expected_len = 0,
//		.expected_res = wdns_res_parse_error,
//	},
	{ /* draft-ietf-dnsop-svcb-https-08  2.1
	     The SvcParamValue is parsed using the character-string decoding
	     algorithm (Appendix A)  */
		.rrtype = WDNS_TYPE_HTTPS,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . key10=\"222",		/* Missing end quote */
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
// TODO: how to test for no rdata, as this also has success for A and TXT
//	{
//		.rrtype = WDNS_TYPE_SVCB,
//		.rrclass = WDNS_CLASS_IN,
//		.input = "",		/* Missing all RDATA */
//		.expected = "",
//		.expected_len = 0,
//		.expected_res = wdns_res_parse_error,
//	},
	{
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "JUNK",		/* Bogus RDATA */
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     SvcPriority is a number in the range 0-65535 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "JUNK .",		/* Bogus SvcPriority */
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     SvcPriority is a number in the range 0-65535 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "-1 .",		/* Invalid SvcPriority range */
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     SvcPriority is a number in the range 0-65535 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "65536 .",		/* Invalid SvcPriority range */
		.expected = "",
		.expected_len = 0,
		.expected_res = wdns_res_parse_error,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.1
	     SvcPriority is a number in the range 0-65535 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "65535 .",		/* Valid SvcPriority range */
		.expected = "\xff\xff\x00",
		.expected_len = 3,
		.expected_res = wdns_res_success,
	},
	{ /* draft-ietf-dnsop-svcb-https-08 2.5.1 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "0 .",		/* AliasMode "." means not available */
		.expected = "\x00\x00\x00",
		.expected_len = 3,
		.expected_res = wdns_res_success,
	},
	{ /* Test that SvcParam may exist so just pass it through.
	     draft-ietf-dnsop-svcb-https-08 2.4.2
	     In AliasMode, records SHOULD NOT include any SvcParams, and
	     recipients MUST ignore any SvcParams that are present. */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "0 . key1=abc",
		.expected = "\x00\x00"			/* priority = AliasMode */
		    "\x00"				/* target . */
		    "\x00\x01"				/* SvcParamKey 1 is alpn */
		    "\x00\x04"				/* length.. */
		    "\x03"				/* alpn length.. */
		    "abc",				/* ..value */
		.expected_len = 11,
		.expected_res = wdns_res_success,
	},
	{ /* same as above but with quotes around alpn (key1) value */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = "1 . key1=\"abc\"",
		.expected = "\x00\x01"			/* priority */
		    "\x00"				/* target . */
		    "\x00\x01"				/* SvcParamKey 1 is alpn */
		    "\x00\x04"				/* length.. */
		    "\x03"				/* alpn length.. */
		    "abc",				/* ..value */
		.expected_len = 11,
		.expected_res = wdns_res_success,
	},

	/* draft-ietf-dnsop-svcb-https-08 */
	{ /* appendix D, figure 9 */
		.rrtype = WDNS_TYPE_SVCB,
		.rrclass = WDNS_CLASS_IN,
		.input = QUOTE(16 foo.example.org. alpn="f\\\\oo\\,bar,h2"),
		.expected = "\x00\x10"			/* priority */
		    "\x03""foo\x07""example\x03org\x00"	/* target */
		    "\x00\x01"				/* alpn */
		    "\x00\x0c"				/* length.. */
		    "\x08"				/* ..value */
		    "f\\oo,bar"
		    "\x02"
		    "h2",
		.expected_len = 35,
		.expected_res = wdns_res_success,
	},
        { /* CAA record, rfc 8659 */
                .rrtype = WDNS_TYPE_CAA,
                .rrclass = WDNS_CLASS_IN,
		.input = "0 \"issue\" \"digicert.com\"",
                .expected = "\x00"				/* flag */
                    "\x05\x69\x73\x73\x75\x65"			/* tag */
                    "\x64\x69\x67\x69\x63\x65\x72\x74\x2e\x63"	/* value */
		    "\x6f\x6d",
		.expected_len = 19,
		.expected_res = wdns_res_success,
        },
	{ 0 }
};

static size_t
test_str_to_rdata(void) {
	ubuf *u;
	size_t failures = 0;

	u = ubuf_init(256);

	for (const struct test *cur = tdata; cur->input != NULL; cur++) {
		uint8_t *actual = NULL;
		size_t actual_len = 0;
		wdns_res res;

		ubuf_reset(u);

		res = wdns_str_to_rdata(cur->input, cur->rrtype, cur->rrclass, &actual, &actual_len);

		if (res != cur->expected_res) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " %s %s res=%s != %s",
					wdns_rrclass_to_str(cur->rrclass),
					wdns_rrtype_to_str(cur->rrtype),
					wdns_res_to_str(res),
					wdns_res_to_str(cur->expected_res));

			if (res == wdns_res_success) {
				ubuf_add_cstr(u, " value=");
				escape(u, actual, actual_len);
			}
			failures++;
		} else if (actual_len != cur->expected_len || memcmp(actual, cur->expected, actual_len)) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));

			ubuf_add_fmt(u, " %s %s",
					wdns_rrclass_to_str(cur->rrclass),
					wdns_rrtype_to_str(cur->rrtype));

			if (actual_len != cur->expected_len) {
				ubuf_add_fmt(u, " len %d != %d",
						actual_len, cur->expected_len);
			}

			ubuf_add_fmt(u, " res=%s",
					wdns_res_to_str(res));

			ubuf_add_cstr(u, " value=");
			escape(u, actual, actual_len);
			ubuf_add_cstr(u, " != ");
			escape(u, cur->expected, cur->expected_len);

			failures++;
		} else {
			char *roundtrip;

			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
			escape(u, (uint8_t*)cur->input, strlen(cur->input));
			ubuf_add_fmt(u, " %s %s res=%s",
					wdns_rrclass_to_str(cur->rrclass),
					wdns_rrtype_to_str(cur->rrtype),
					wdns_res_to_str(res));

			if (res == wdns_res_success) {
				ubuf_add_cstr(u, " value=");
				escape(u, actual, actual_len);
			}

			if (cur->expected_res != wdns_res_parse_error) {
				/*
				 * Send the result of the first test, which
				 * processed an string into an rdata, through a
				 * 'round trip' test back from rdata to string
				 * and compare the end result with the initial
				 * string.
				 */
				roundtrip = wdns_rdata_to_str(actual,
				    actual_len, cur->rrtype, cur->rrclass);

				if (roundtrip == NULL) {
					ubuf_add_fmt(u, "\nFAIL %" PRIu64
					    ": round trip failed, "
					    "rrtype=%s input=",
					    cur - tdata,
					    wdns_rrtype_to_str(cur->rrtype),
					    cur->input);

					escape(u, (const uint8_t*)cur->input,
					    strlen(cur->input));
					failures++;

				} else if (strncasecmp(cur->input, roundtrip,
				    strlen(cur->input)) != 0) {
					/*
					 * The round trip string differs from the
					 * original input. Verify that both strings
					 * encode the same rdata.
					 */
					free(actual);
					actual = NULL;

					res = wdns_str_to_rdata(roundtrip,
					    cur->rrtype, cur->rrclass, &actual,
					    &actual_len);
					if (res != wdns_res_success) {
						ubuf_add_fmt(u,
						    "\nFAIL %" PRIu64
						    ": round trip res=%s,"
						    "rrtype=%s input=",
						    cur - tdata,
						    wdns_res_to_str(res),
						    wdns_rrtype_to_str(
							    cur->rrtype));
						escape(u,
						    (const uint8_t *)roundtrip,
						    strlen(roundtrip));
						failures++;

					} else if ((actual_len !=
					    cur->expected_len) ||
						memcmp(actual, cur->expected,
						    actual_len)) {
						ubuf_add_fmt(u,
						    "\nFAIL %" PRIu64
						    ": round trip mismatch, "
						    "rrtype=%s input=",
						    cur - tdata,
						    wdns_rrtype_to_str(
						    cur->rrtype));
						escape(u,
						    (const uint8_t *)roundtrip,
						    strlen(roundtrip));
						ubuf_add_cstr(u, " value=");
						escape(u, actual, actual_len);
						ubuf_add_cstr(u, " != ");
						escape(u, cur->expected,
						    cur->expected_len);
						failures++;
					} else {
						ubuf_add_fmt(u,
						    "\nPASS %" PRIu64
						    ": round trip match, "
						    "rrtype=%s roundtrip=",
						    cur - tdata,
						    wdns_rrtype_to_str(
						    cur->rrtype));
						escape(u,
						    (const uint8_t *)roundtrip,
						    strlen(roundtrip));
						ubuf_add_cstr(u, " value=");
						escape(u, actual, actual_len);
					}

					free(roundtrip);
				} else {
					free(roundtrip);
				}
			}
		}

		fprintf (stderr, "%s\n", ubuf_cstr(u));
		if (actual != NULL) {
			free(actual);
			actual = NULL;
		}
	}

	ubuf_destroy(&u);
	return failures;
}

int main (void) {
	int ret = 0;

	ret |= check(test_str_to_rdata(), "test_str_to_rdata", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
