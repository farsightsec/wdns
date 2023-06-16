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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-rdata"

struct test {
	const void *input;
	size_t input_len;
	uint16_t rrtype;
	uint16_t rrclass;
	const char *expected;
	bool skip_round_trip;
};

struct test tdata[] = {
	/* rrtype bitmap test for rrtypes > 255 */
	{
		.input = "\x01\x01\x00\x00\x00\x01\x00\x00\x01\x42",
		.input_len = 10,
		.rrtype = WDNS_TYPE_NSEC3,
		.rrclass = WDNS_CLASS_IN,
		.expected = "1 1 0 - 00 A SOA",
	},
	{ "\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef", 17, WDNS_TYPE_A6, WDNS_CLASS_IN, "0 2000::dead:beef" },
	{ "\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x03""fsi\x02io\x00", 24, WDNS_TYPE_A6, WDNS_CLASS_IN, "8 ::222.173.190.239 fsi.io." },
	{ "\x80\x03""fsi\x02io\x00", 9, WDNS_TYPE_A6, WDNS_CLASS_IN, "128 fsi.io." },

	{
		.input = "\x00\x0a" "\x00\x01" "ftp://ftp1.example.com/public",
		.input_len = 2 + 2 + 29,
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.expected = "10 1 \"ftp://ftp1.example.com/public\"",
	},

	{
		.input = "\x00\x0a" "\x00\x01"
			"https://www.isc.org/HolyCowThisSureIsAVeryLongURIRecordIDontEvenKnowWhatSomeoneWouldEverWantWithSuchAThingButTheSpecificationRequiresThatWesupportItSoHereWeGoTestingItLaLaLaLaLaLaLaSeriouslyThoughWhyWouldYouEvenConsiderUsingAURIThisLongItSeemsLikeASillyIdeaButEnhWhatAreYouGonnaDo/",
		.input_len = 2 + 2 + 281,
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.expected = "10 1 " "\"" "https://www.isc.org/HolyCowThisSureIsAVeryLongURIRecordIDontEvenKnowWhatSomeoneWouldEverWantWithSuchAThingButTheSpecificationRequiresThatWesupportItSoHereWeGoTestingItLaLaLaLaLaLaLaSeriouslyThoughWhyWouldYouEvenConsiderUsingAURIThisLongItSeemsLikeASillyIdeaButEnhWhatAreYouGonnaDo/" "\"",
	},

	{
		.input = "\x04" "some" "\x04" "text",
		.input_len = 1 + 4 + 1 + 4,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"some\" \"text\"",
	},

	/* TXT test for: a string beginning with a " and ending with a " */
	{
		.input = "\x08" "\x22" "quoted" "\x22",
		.input_len = 1 + 1 + 6 + 1,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"\\\"quoted\\\"\"",
	},

	/* TXT test for: one quote sent over the wire */
	{
		.input = "\x03" "one" "\x05" "quote" "\x01" "\"" "\x04" "sent" "\x04" "over" "\x03" "the" "\x04" "wire",
		.input_len = 1 + 3 + 1 + 5 + 1 + 1 + 1 + 4 + 1 + 4 + 1 + 3 + 1 + 4,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"one\" \"quote\" \"\\\"\" \"sent\" \"over\" \"the\" \"wire\"",
	},

	/* TXT test for: 256 characters in length (including the length
	   octet) */
	{
		.input = "\xff" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.input_len = 1 + 255,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
	},

	/* TXT test for: single character string with multiple spaces */
	{
		.input = "\x19" "one string multiple words",
		.input_len = 1 + 25,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"one string multiple words\"",
	},

	/* TXT test for: multiple character strings with spaces */
	{
		.input = "\x10" "multiple strings" "\x02" "of" "\x0e" "multiple words",
		.input_len = 1 + 16 + 1 + 2 + 1+ 14,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"multiple strings\" \"of\" \"multiple words\"",
	},

	/* TXT test for: multiple long character strings */
	{
		.input = "\xff" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "\xff" "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" "\xff" "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		.input_len = 1 + 255 + 1 + 255 + 1 + 255,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" \"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\" \"ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"",
	},

	/* TXT test for: real world example of DKIM use.
	   The total length was 411 charcters broke up into
	   multiple character-strings. */
	{
		.input = "\xfe" "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2UMfREvlgajdSp3jv1tJ9nLpi/mRYnGyKC3inEQ9a7zqUjLq/yXukgpXs9AEHlvBvioxlgAVCPQQsuc1xp9+KXQGgJ8jTsn5OtKm8u+YBCt6OfvpeCpvt0l9JXMMHBNYV4c0XiPE5RHX2ltI0Av20CfEy+vMecpFtVDg4rMngjLws/ro6qT63S20A4zyVs/V" "\x9c" "19WW5F2Lulgv+l+EJzz9XummIJHOlU5n5ChcWU3Rw5RVGTtNjTZnFUaNXly3fW0ahKcG5Qc3e0Rhztp57JJQTl3OmHiMR5cHsCnrl1VnBi3kaOoQBYsSuBm+KRhMIw/X9wkLY67VLdkrwlX3xxsp6wIDAQAB",
		.input_len = 1 + 254 + 1 + 156,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
/* NOTE: the semicolons are not escaped as they would be with dig output */
		.expected = "\"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2UMfREvlgajdSp3jv1tJ9nLpi/mRYnGyKC3inEQ9a7zqUjLq/yXukgpXs9AEHlvBvioxlgAVCPQQsuc1xp9+KXQGgJ8jTsn5OtKm8u+YBCt6OfvpeCpvt0l9JXMMHBNYV4c0XiPE5RHX2ltI0Av20CfEy+vMecpFtVDg4rMngjLws/ro6qT63S20A4zyVs/V\" \"19WW5F2Lulgv+l+EJzz9XummIJHOlU5n5ChcWU3Rw5RVGTtNjTZnFUaNXly3fW0ahKcG5Qc3e0Rhztp57JJQTl3OmHiMR5cHsCnrl1VnBi3kaOoQBYsSuBm+KRhMIw/X9wkLY67VLdkrwlX3xxsp6wIDAQAB\"",
	},

	/* TXT test from RFC 7208 section 3.3:
	   concatenated together without adding spaces. */
	{
		.input = "\x11" "v=spf1 .... first" "\x10" "second string...",
		.input_len = 1 + 17 + 1 + 16,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"v=spf1 .... first\" \"second string...\"",
	},

	/* SPF test using real world example, all as one string */
	{
		.input = "\x63" "v=spf1 a mx ip4:204.152.184.0/21 ip4:149.20.0.0/16 ip6:2001:04F8::0/32 ip6:2001:500:60::65/128 ~all",
		.input_len = 1 + 99,
		.rrtype = WDNS_TYPE_SPF,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"v=spf1 a mx ip4:204.152.184.0/21 ip4:149.20.0.0/16 ip6:2001:04F8::0/32 ip6:2001:500:60::65/128 ~all\"",
	},

	{
		.input =
			"\x1a" "Please stop asking for ANY"
			"\x1f" "See draft-ietf-dnsop-refuse-any"
			,
		.input_len = 1 + 0x1a + 1 + 0x1f,
		.rrtype = WDNS_TYPE_HINFO,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"Please stop asking for ANY\" \"See draft-ietf-dnsop-refuse-any\"",
	},

	{
		.input =
			"\x00\x00\x00\x42"
			"\x00\x03"
			"\x00\x04\x60\x00\x00\x08"
			,
		.input_len = 4 + 2 + 6,
		.rrtype = WDNS_TYPE_CSYNC,
		.rrclass = WDNS_CLASS_IN,
		.expected = "66 3 A NS AAAA",
	},

	{
		.input = "\xAB\xCD\xEF\x01\x02\x03",
		.input_len = 6,
		.rrtype = WDNS_TYPE_EUI48,
		.rrclass = WDNS_CLASS_IN,
		.expected = "ab-cd-ef-01-02-03",
	},

	{
		.input = "\xAB\xCD\xEF\x01\x02\x03\x04\x05",
		.input_len = 8,
		.rrtype = WDNS_TYPE_EUI64,
		.rrclass = WDNS_CLASS_IN,
		.expected = "ab-cd-ef-01-02-03-04-05",
	},

	{
		.input = "\x01\x02\x03\x04\x05\x06\x07\x08",
		.input_len = 8,
		.rrtype = WDNS_TYPE_OPENPGPKEY,
		.rrclass = WDNS_CLASS_IN,
		.expected = "AQIDBAUGBwg=",
	},

	{
		.input =
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
		.input_len = 2 + 1 + 1 + 130,
		.rrtype = WDNS_TYPE_CDNSKEY,
		.rrclass = WDNS_CLASS_IN,
		.expected =
			"256 3 5 "
			"AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no"
			"kfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6z"
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1U"
			"aNvv4w==",
	},

	{
		.input =
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
		.input_len = 2 + 1 + 1 + 130,
		.rrtype = WDNS_TYPE_DNSKEY,
		.rrclass = WDNS_CLASS_IN,
		.expected =
			"256 3 5 "
			"AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no"
			"kfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6z"
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1U"
			"aNvv4w==",
	},

	{
		.input =
			"\xec\x45" "\x05" "\x01"
			"\x2b\xb1\x83\xaf\x5f\x22\x58\x81\x79\xa5\x3b\x0a\x98\x63\x1f\xad\x1a\x29\x21\x18",
		.input_len = 2 + 1 + 1 + 20,
		.rrtype = WDNS_TYPE_DS,
		.rrclass = WDNS_CLASS_IN,
		.expected = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
	},

	{
		.input =
			"\xec\x45" "\x05" "\x01"
			"\x2b\xb1\x83\xaf\x5f\x22\x58\x81\x79\xa5\x3b\x0a\x98\x63\x1f\xad\x1a\x29\x21\x18",
		.input_len = 2 + 1 + 1 + 20,
		.rrtype = WDNS_TYPE_CDS,
		.rrclass = WDNS_CLASS_IN,
		.expected = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
	},

	{
		.input =
			"\x00" "\x00" "\x01"
			"\xd2\xab\xde\x24\x0d\x7c\xd3\xee\x6b\x4b\x28\xc5\x4d\xf0\x34\xb9"
			"\x79\x83\xa1\xd1\x6e\x8a\x41\x0e\x45\x61\xcb\x10\x66\x18\xe9\x71",
		.input_len = 1 + 1 + 1 + 32,
		.rrtype = WDNS_TYPE_TLSA,
		.rrclass = WDNS_CLASS_IN,
		.expected =
			"0 0 1 "
			"D2ABDE240D7CD3EE6B4B28C54DF034B9"
			"7983A1D16E8A410E4561CB106618E971",
	},

	/* rrtype bitmap test for rrtypes > 255 */
	{
		.input =
			"\x03""fsi\x02io\x00"
			"\x00\x01" "\x40"
			"\x01\x01" "\x40"
			"\x80\x01" "\x40",
		.input_len = 8 + 3 + 3 + 3,
		.rrtype = WDNS_TYPE_NSEC,
		.rrclass = WDNS_CLASS_IN,
		.expected = "fsi.io. A CAA DLV",
	},

	/* draft-ietf-dnsop-svcb-https-08 */
	{ /* appendix D, figure 1 */
		.input = "\x00\x00"				/* priority */
		    "\x03""foo\x07""example\x03""com\x00",	/* target */
		.input_len = 19,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_HTTPS,
		.expected = "0 foo.example.com.",
	},

	{ /* appendix D, figure 2 */
		.input = "\x00\x01"				/* priority */
		    "\x00",					/* target */
		.input_len = 3,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_HTTPS,
		.expected = "1 .",
	},

	{ /* appendix D, figure 3 */
		.input = "\x00\x10"				/* priority */
		    "\x03""foo\x07""example\x03""com\x00"	/* target */
		    "\x00\x03"					/* port */
		    "\x00\x02"					/* length.. */
		    "\x00\x35",					/* ..value */
		.input_len = 25,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_SVCB,
		.expected = "16 foo.example.com. port=53",
	},

	{ /* appendix D, figure 4 */
		.input = "\x00\x01"				/* priority */
		    "\x03""foo\x07""example\x03""com\x00"	/* target */
		    "\x02\x9b"					/* 667 */
		    "\x00\x05"					/* length.. */
		    "hello",					/* ..value */
		.input_len = 28,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_SVCB,
		.expected = "1 foo.example.com. key667=\"hello\"",
	},

	{ /* appendix D, figure 5 */
		.input = "\x00\x01"				/* priority */
		    "\x03""foo\x07""example\x03""com\x00"	/* target */
		    "\x02\x9b"					/* 667 */
		    "\x00\x09"					/* length.. */
		    "hello\xd2qoo",				/* ..value */
		.input_len = 32,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_SVCB,
		.expected = "1 foo.example.com. key667=\"hello\\210qoo\"",
	},

	{ /* appendix D, figure 6 */
		.input = "\x00\x01"				/* priority */
		    "\x03""foo\x07""example\x03""com\x00"	/* target */
		    "\x00\x06"					/* ipv6hint */
		    "\x00\x20"					/* length.. */
		    "\x20\x01\x0d\xb8\x00\x00\x00\x00"		/* ..value */
		    "\x00\x00\x00\x00\x00\x00\x00\x01"
		    "\x20\x01\x0d\xb8\x00\x00\x00\x00"
		    "\x00\x00\x00\x00\x00\x53\x00\x01",
		.input_len = 55,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_SVCB,
		.expected = "1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1",
	},

	{ /* appendix D, figure 7 */
		.input = "\x00\x01"				/* priority */
		    "\x07""example\x03""com\x00"		/* target */
		    "\x00\x06"					/* ipv6hint */
		    "\x00\x10"					/* length.. */
		    "\x00\x00\x00\x00\x00\x00\x00\x00"		/* ..value */
		    "\x00\x00\xff\xff\xc6\x33\x64\x64",
		.input_len = 35,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_SVCB,
		.expected = "1 example.com. ipv6hint=::ffff:198.51.100.100",
	},

	/* appendix D, figure 8 is omitted as it relies on re-ordering params */

	{ /* appendix D, figure 9 (reverse test) */
                .input = "\x00\x10"				/* priority */
                    "\x03""foo\x07""example\x03org\x00"		/* target */
                    "\x00\x01"					/* alpn */
                    "\x00\x0c"					/* length.. */
                    "\x08"					/* ..value */
                    "f\\oo,bar"
                    "\x02"
                    "h2",
                .input_len = 35,
                .rrclass = WDNS_CLASS_IN,
                .rrtype = WDNS_TYPE_SVCB,
		.expected = QUOTE(16 foo.example.org. alpn="f\\\\oo\\,bar,h2"),
        },

	{ /* HTTPS test with alpn and ipv4hint */
		.input = "\x00\x01"				/* priority */
		    "\x00"					/* target */
		    "\x00\x01"					/* alpn */
		    "\x00\x03"					/* length.. */
		    "\x02\x68\x32"				/* ..value */
		    "\x00\x04"					/* ipv4hint */
		    "\x00\x04"					/* length.. */
		    "\xc0\xa8\x00\x01",				/* ..value */
		.input_len = 18,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_HTTPS,
		.expected = "1 . alpn=\"h2\" ipv4hint=192.168.0.1",
	},

	{ /* HTTPS test for an arbitrary key type 9 */
		.input = "\x00\x01"				/* priority */
		    "\x00"					/* target */
		    "\x00\x01"					/* alpn */
		    "\x00\x03"					/* length.. */
		    "\x02\x68\x32"				/* ..value */
		    "\x00\x09"					/* 9 */
		    "\x00\x03"					/* length.. */
		    "\x61\x6e\x79",				/* ..value */
		.input_len = 17,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_HTTPS,
		.expected = "1 . alpn=\"h2\" key9=\"any\"",
	},

	{ /* CAA record, rfc 8659 */
		.input = "\x00"					/* flag */
		    "\x09\x69\x73\x73\x75\x65\x77\x69\x6c\x64"	/* tag */
		    "\x6c\x65\x74\x73\x65\x6e\x63\x72\x79\x70"	/* value */
		    "\x74\x2e\x6f\x72\x67",
		.input_len = 26,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_CAA,
		.expected = "0 \"issuewild\" \"letsencrypt.org\"",
	},


	/* EDNS OPT records, RFC 6891, 7871, and 8914*/
	{ /* IPv4 Client-Subnet */
		.input = "\x00\x08"	/* option code */
		    "\x00\x07"		/* option length */
		    "\x00\x01"		/* iana addr family */
		    "\x18"		/* source prefix-length */
		    "\x16"		/* scope prefix-length */
		    "\xc7\x1e\xe4",	/* address */
		.input_len = 11,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET: 199.30.228.0/24/22",
		.skip_round_trip = true,
	},

	{ /* IPv6 Client-Subnet */
		.input = "\x00\x08"				/* option code */
		    "\x00\x0b"					/* option length */
		    "\x00\x02"					/* iana addr family */
		    "\x38"					/* source prefix-length */
		    "\x30"					/* scope prefix-length */
		    "\x26\x20\x01\x1c\xf0\x08\x00",		/* address */
		.input_len = 15,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET: 2620:11c:f008::/56/48",
		.skip_round_trip = true,
	},

	{ /* Extended DNS Error, DNSKEY Missing */
		.input = "\x00\x0f"				/* option code */
		    "\x00\x35"					/* option length */
		    "\x00\x09"					/* info code */
		    /* extra text */
		    "\x6e\x6f\x20\x53\x45\x50\x20\x6d\x61\x74\x63\x68\x69\x6e\x67\x20\x74\x68\x65\x20\x44\x53\x20\x66\x6f\x75\x6e\x64\x20\x66\x6f\x72\x20\x64\x6e\x73\x73\x65\x63\x2d\x66\x61\x69\x6c\x65\x64\x2e\x6f\x72\x67\x2e",
		.input_len = 57,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; EDE: 9 (DNSKEY Missing): (no SEP matching the DS found for dnssec-failed.org.)",
		.skip_round_trip = true,
	},

	{ /* Extended DNS Error, Reserved for Private Use (49152)*/
		.input = "\x00\x0f"				/* option code */
		    "\x00\x31"					/* option length */
		    "\xc0\x00"					/* info code */
		    /* extra text */
		    "\x54\x68\x65\x73\x65\x20\x63\x68\x61\x72\x73\x20\x61\x72\x65\x20\x70\x72\x69\x6e\x74\x61\x62\x6c\x65\x2e\x20\x54\x68\x65\x73\x65\x20\x61\x72\x65\x20\x6e\x6f\x74\x3a\x00\x02\x0d\x08\x03\x04",
		.input_len = 53,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; EDE: 49152: (These chars are printable. These are not:......)",
		.skip_round_trip = true,
	},

	{ /* OPT=6 and OPT=7 handled in default manner */
		.input = "\x00\x06"	/* option code */
		"\x00\x03"		/* option length */
		"\x01\x02\x04"		/* option data */
		"\x00\x07"		/* option code */
		"\x00\x01"		/* option length */
		"\x01",			/* option data */
		.input_len = 12,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; OPT=6: 01 02 04 (\"...\")\n; OPT=7: 01 (\".\")",
		.skip_round_trip = true,
	},

	{ /* Record with no option data */
		.input = "\x00\x05"	/* option code */
		"\x00\x03",		/* option length */
					/* missing option data */
		.input_len = 4,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; OPT=5: ### PARSE ERROR ###",
		.skip_round_trip = true,
	},

	{ /* IPv4 Client-Subnet but without scope bytes */
		.input = "\x00\x08"	/* option code */
		    "\x00\x07"		/* option length */
		    "\x00\x01"		/* iana addr family */
		    "\x18"		/* source prefix-length */
					/* missing scope prefix-length */
		    "\xc7\x1e\xe4",	/* address */
		.input_len = 10,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET: ### PARSE ERROR ###",
		.skip_round_trip = true,
	},

	{ /* IPv4 Client-Subnet but without address bytes*/
		.input = "\x00\x08"	/* option code */
		    "\x00\x07"		/* option length */
		    "\x00\x01"		/* iana addr family */
		    "\x18"		/* source prefix-length */
		    "\x16",		/* scope prefix-length */
					/* missing address */
		.input_len = 8,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET: ### PARSE ERROR ###",
		.skip_round_trip = true,
	},

	{ /* IPv6 Client-Subnet but with wrong addr_family */
		.input = "\x00\x08"				/* option code */
		    "\x00\x0b"					/* option length */
		    "\x00\01"					/* wrong (IPv4) iana addr family */
		    "\x38"					/* source prefix-length */
		    "\x30"					/* scope prefix-length */
		    "\x26\x20\x01\x1c\xf0\x08\x00",		/* address */
		.input_len = 15,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET:  ### PARSE ERROR #12 ###",
		.skip_round_trip = true,
	},

	{ /* IPv6 Client-Subnet but with invalid addr family */
		.input = "\x00\x08"				/* option code */
		    "\x00\x0b"					/* option length */
		    "\x00\x03"					/* invalid (3) iana addr family */
		    "\x38"					/* source prefix-length */
		    "\x30"					/* scope prefix-length */
		    "\x26\x20\x01\x1c\xf0\x08\x00",		/* address */
		.input_len = 15,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; CLIENT-SUBNET:  ### PARSE ERROR #12 ###",
		.skip_round_trip = true,
	},

	{ /* Extended DNS Error but without enough octets for info code */
		.input = "\x00\x0f"				/* option code */
		    "\x00\x01"					/* option length */
		    "\x00",					/* invalid single octet info code */
		.input_len = 5,
		.rrclass = WDNS_CLASS_IN,
		.rrtype = WDNS_TYPE_OPT,
		.expected = "\n; EDE:  ### PARSE ERROR #12 ###",
		.skip_round_trip = true,
	},

	{ 0 }
};

static size_t
_test_str_to_rdata(const char *rdata_str, const struct test *cur, const ubuf **up) {
	uint8_t *rdata = NULL;
	size_t rdlen = 0;
	wdns_res res;
	size_t failure = 0;
	ubuf *u = (ubuf *)*up;

	res = wdns_str_to_rdata(rdata_str, cur->rrtype, cur->rrclass, &rdata,
		&rdlen);

	if (res != wdns_res_success) {
	        ubuf_add_fmt(u, "\nFAIL %" PRIu64
		    ": round trip parsing failed (%s), "
		    "rrtype=%s input=",
		    cur - tdata, wdns_res_to_str(res),
		    wdns_rrtype_to_str(cur->rrtype), rdata_str);

		escape(u, (const uint8_t*)rdata_str,
		    strlen(rdata_str));
	        failure++;
	} else {
		if (rdlen != cur->input_len ||
		    memcmp(rdata, cur->input, cur->input_len)) {
		        ubuf_add_fmt(u, "\nFAIL %" PRIu64
			    " (round trip): parsed=",
			    cur - tdata);
		        escape(u, rdata, rdlen);
		        failure++;
		}
	}
	free(rdata);
	return failure;
}

static size_t
test_rdata_to_str(void) {
	ubuf *u;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);

	for(cur = tdata; cur->input != NULL; cur++) {
		char * actual = NULL;

		ubuf_reset(u);

		actual = wdns_rdata_to_str(cur->input, cur->input_len, cur->rrtype, cur->rrclass);

		if (strcmp(actual, cur->expected)) {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			escape(u, cur->input, cur->input_len);

			ubuf_add_fmt(u, " %s %s",
					wdns_rrclass_to_str(cur->rrclass),
					wdns_rrtype_to_str(cur->rrtype));

			ubuf_add_cstr(u, " value=");
			escape(u, (const uint8_t*)actual, strlen(actual));
			ubuf_add_cstr(u, " != ");
			escape(u, (const uint8_t*)cur->expected, strlen(cur->expected));

			failures++;
		} else {
			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
			escape(u, cur->input, cur->input_len);
			ubuf_add_fmt(u, " %s %s",
					wdns_rrclass_to_str(cur->rrclass),
					wdns_rrtype_to_str(cur->rrtype));

			ubuf_add_cstr(u, " value=");
			escape(u, (const uint8_t*)actual, strlen(actual));

			if (!cur->skip_round_trip) {
				/*
				 * Send the result of the first test, which processed
				 * an rdata input into a string, through a 'round trip'
				 * test back from string to rdata and compare the
				 * end result with the initial rdata.
				 */
				failures += _test_str_to_rdata(
					(const char*)actual,
					(const struct test *)cur,
					(const ubuf **)&u);
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

static size_t
test_parse_message(void)
{
	const uint8_t header[] = {
		0, 0,		/* id */
		0x80, 0,	/* QR bit, rcode 0 (NOERROR) */
		0, 1,		/* QDCOUNT: 1 */
		0, 1, 		/* ANCOUNT: 1 */
		0, 0,		/* NSCOUNT: 0 */
		0, 0,		/* ARCOUNT: 0 */
	};
	const uint8_t dname[] = "\x07""example\x03""com";

	ubuf *u, *umsg;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);
	umsg = ubuf_init(512);
	ubuf_append(umsg, header, sizeof(header));

	for(cur = tdata; cur->input != NULL; cur++) {

		uint16_t rrtype, rrclass, rdlen;
		uint32_t rrttl = htonl(3600);
		wdns_message_t m;
		wdns_res res;

		ubuf_clip(umsg, sizeof(header));
		ubuf_reset(u);

		rrtype = htons(cur->rrtype);
		rrclass = htons(cur->rrclass);
		rdlen = htons(cur->input_len);

		/* question section */
		ubuf_append(umsg, dname, sizeof(dname));
		ubuf_append(umsg, (uint8_t *)&rrtype, sizeof(rrtype));
		ubuf_append(umsg, (uint8_t *)&rrclass, sizeof(rrclass));

		/* answer section */
		ubuf_append(umsg, dname, sizeof(dname));
		ubuf_append(umsg, (uint8_t *)&rrtype, sizeof(rrtype));
		ubuf_append(umsg, (uint8_t *)&rrclass, sizeof(rrclass));
		ubuf_append(umsg, (uint8_t *)&rrttl, sizeof(rrttl));
		ubuf_append(umsg, (uint8_t *)&rdlen, sizeof(rdlen));
		ubuf_append(umsg, cur->input, cur->input_len);

		res = wdns_parse_message(&m, ubuf_data(umsg), ubuf_size(umsg));

		if (res == wdns_res_success) {
			ubuf_add_fmt(u, "PASS %" PRIu64 ": input=", cur-tdata);
		} else {
			ubuf_add_fmt(u, "FAIL %" PRIu64 ": input=", cur-tdata);
			failures++;
		}
		escape(u, cur->input, cur->input_len);
		ubuf_add_fmt(u, " %s %s",
				wdns_rrclass_to_str(cur->rrclass),
				wdns_rrtype_to_str(cur->rrtype));
		fprintf (stderr, "%s\n", ubuf_cstr(u));
		wdns_clear_message(&m);
	}

	ubuf_destroy(&u);
	ubuf_destroy(&umsg);
	return failures;
}

int main (void) {
	int ret = 0;

	ret |= check(test_rdata_to_str(), "test_rdata_to_str", NAME);
	ret |= check(test_parse_message(), "test_parse_message", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
