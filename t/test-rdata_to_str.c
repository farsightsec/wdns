#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-rdata_to_str"

struct test {
	const void *input;
	size_t input_len;
	uint16_t rrtype;
	uint16_t rrclass;
	const char *expected;
};

struct test tdata[] = {
	{ "\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef", 17, WDNS_TYPE_A6, WDNS_CLASS_IN, "0 2000::dead:beef" },
	{ "\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x03""fsi\x02io\x00", 25, WDNS_TYPE_A6, WDNS_CLASS_IN, "1 2000::dead:beef fsi.io." },
	{ "\x80\x03""fsi\x02io\x00", 9, WDNS_TYPE_A6, WDNS_CLASS_IN, "128 fsi.io." },
	{ "\x80", 1, WDNS_TYPE_A6, WDNS_CLASS_IN, "128" },

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
			"AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no "
			"kfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6z "
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1U "
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
			"AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no "
			"kfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6z "
			"Mv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1U "
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

	{ 0 }
};


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

	ret |= check(test_rdata_to_str(), "test_rdata_to_str", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
