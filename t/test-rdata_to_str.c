#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-rdata_to_str"

struct test {
	const uint8_t * input;
	size_t input_len;
	uint16_t rrtype;
	uint16_t rrclass;
	const char *expected;
};

struct test tdata[] = {
	{ (const uint8_t*)"\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef", 17, WDNS_TYPE_A6, WDNS_CLASS_IN, "0 2000::dead:beef" },
	{ (const uint8_t*)"\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x03""fsi\x02io\x00", 25, WDNS_TYPE_A6, WDNS_CLASS_IN, "1 2000::dead:beef fsi.io." },
	{ (const uint8_t*)"\x80\x03""fsi\x02io\x00", 9, WDNS_TYPE_A6, WDNS_CLASS_IN, "128 fsi.io." },
	{ (const uint8_t*)"\x80", 1, WDNS_TYPE_A6, WDNS_CLASS_IN, "128" },

	{
		.input = (const uint8_t *) "\x00\x0a" "\x00\x01" "ftp://ftp1.example.com/public",
		.input_len = 2 + 2 + 29,
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.expected = "10 1 \"ftp://ftp1.example.com/public\"",
	},

	{
		.input = (const uint8_t *) "\x00\x0a" "\x00\x01"
			"https://www.isc.org/HolyCowThisSureIsAVeryLongURIRecordIDontEvenKnowWhatSomeoneWouldEverWantWithSuchAThingButTheSpecificationRequiresThatWesupportItSoHereWeGoTestingItLaLaLaLaLaLaLaSeriouslyThoughWhyWouldYouEvenConsiderUsingAURIThisLongItSeemsLikeASillyIdeaButEnhWhatAreYouGonnaDo/",
		.input_len = 2 + 2 + 281,
		.rrtype = WDNS_TYPE_URI,
		.rrclass = WDNS_CLASS_IN,
		.expected = "10 1 " "\"" "https://www.isc.org/HolyCowThisSureIsAVeryLongURIRecordIDontEvenKnowWhatSomeoneWouldEverWantWithSuchAThingButTheSpecificationRequiresThatWesupportItSoHereWeGoTestingItLaLaLaLaLaLaLaSeriouslyThoughWhyWouldYouEvenConsiderUsingAURIThisLongItSeemsLikeASillyIdeaButEnhWhatAreYouGonnaDo/" "\"",
	},

	{
		.input = (const uint8_t *) "\x04" "some" "\x04" "text",
		.input_len = 1 + 4 + 1 + 4,
		.rrtype = WDNS_TYPE_TXT,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"sometext\"",
	},

	{
		.input = (const uint8_t *)
			"\x1a" "Please stop asking for ANY"
			"\x1f" "See draft-ietf-dnsop-refuse-any"
			,
		.input_len = 1 + 0x1a + 1 + 0x1f,
		.rrtype = WDNS_TYPE_HINFO,
		.rrclass = WDNS_CLASS_IN,
		.expected = "\"Please stop asking for ANY\" \"See draft-ietf-dnsop-refuse-any\"",
	},

	{
		.input = (const uint8_t *)
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
		.input = (const uint8_t *) "\xAB\xCD\xEF\x01\x02\x03",
		.input_len = 6,
		.rrtype = WDNS_TYPE_EUI48,
		.rrclass = WDNS_CLASS_IN,
		.expected = "ab-cd-ef-01-02-03",
	},

	{
		.input = (const uint8_t *) "\xAB\xCD\xEF\x01\x02\x03\x04\x05",
		.input_len = 8,
		.rrtype = WDNS_TYPE_EUI64,
		.rrclass = WDNS_CLASS_IN,
		.expected = "ab-cd-ef-01-02-03-04-05",
	},

	{
		.input = (const uint8_t *) "\x01\x02\x03\x04\x05\x06\x07\x08",
		.input_len = 8,
		.rrtype = WDNS_TYPE_OPENPGPKEY,
		.rrclass = WDNS_CLASS_IN,
		.expected = "AQIDBAUGBwg=",
	},

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

	ret |= check(test_rdata_to_str(), "test_rdata_to_str");

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
