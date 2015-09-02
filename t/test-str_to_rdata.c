#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-str_to_rdata"

struct test {
	char * input;
	uint16_t rrtype;
	uint16_t rrclass;
	const uint8_t *expected;
	size_t expected_len;
	wdns_res expected_res;
};

struct test tdata[] = {
	{ "fsi.io.", WDNS_TYPE_CNAME, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "fsi.io", WDNS_TYPE_CNAME, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "fsi.io..", WDNS_TYPE_CNAME, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ ".", WDNS_TYPE_CNAME, WDNS_CLASS_IN, (const uint8_t*)"\x00", 1, wdns_res_success},
	{ "", WDNS_TYPE_CNAME, WDNS_CLASS_IN, (const uint8_t*)"", 0, wdns_res_success},
	{ "\"hardware\" \"os\"", WDNS_TYPE_HINFO, WDNS_CLASS_IN, (const uint8_t*)"\x08hardware\x02os", 12, wdns_res_success},
	{ "hardware os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, (const uint8_t*)"\x08hardware\x02os", 12, wdns_res_success},
	{ "hardware\\\" os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, (const uint8_t*)"\x09hardware\"\x02os", 13, wdns_res_success},
	{ "hardware\\032 os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, (const uint8_t*)"\x09hardware \x02os", 13, wdns_res_success},
	{ "hardware\\03a os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware\\256 os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware\\n os", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware os\\", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "hardware os\x01", WDNS_TYPE_HINFO, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi.io. farsightsecurity.com", WDNS_TYPE_MINFO, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00\x10""farsightsecurity\x03""com\x00", 30, wdns_res_success },
	{ "fsi.io.", WDNS_TYPE_MINFO, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success },
	{ "", WDNS_TYPE_MINFO, WDNS_CLASS_IN, (const uint8_t*)"", 0, wdns_res_success },
	{ "5 mail.fsi.io.", WDNS_TYPE_MX, WDNS_CLASS_IN, (const uint8_t*)"\x00\x05\x04mail\x03""fsi\x02io\x00", 15, wdns_res_success },
	{ "foo mail.fsi.io.", WDNS_TYPE_MX, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "5", WDNS_TYPE_MX, WDNS_CLASS_IN, (const uint8_t*)"\x00\x05", 2, wdns_res_success },
	{ "", WDNS_TYPE_MX, WDNS_CLASS_IN, (const uint8_t*)0, 0, wdns_res_success },
	{ "", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"", 0, wdns_res_success},
	{ "05", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"\x05", 1, wdns_res_success},
	{ "FF05", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"\xff\x05", 2, wdns_res_success},
	{ "ABFF05", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"\xab\xff\x05", 3, wdns_res_success},
	{ "abff05", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"\xab\xff\x05", 3, wdns_res_success},
	{ "abcdff05", WDNS_TYPE_NULL, WDNS_CLASS_IN, (const uint8_t*)"\xab\xcd\xff\x05", 4, wdns_res_success},
	{ "5", WDNS_TYPE_NULL, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "12345", WDNS_TYPE_NULL, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error },
	{ "fsi.io. root.fsi.io. 65536 1024 127 33554432 0", WDNS_TYPE_SOA, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00\x04root\x03""fsi\x02io\x00\x00\x01\x00\x00\x00\x00\x04\x00\x00\x00\x00\x7f\x02\x00\x00\x00\x00\x00\x00\x00", 41, wdns_res_success },
	{ "", WDNS_TYPE_TXT, WDNS_CLASS_IN, (const uint8_t*)"", 0, wdns_res_success},
	{ "txt", WDNS_TYPE_TXT, WDNS_CLASS_IN, (const uint8_t*)"\x03txt", 4, wdns_res_success},
	{ "txt rec", WDNS_TYPE_TXT, WDNS_CLASS_IN, (const uint8_t*)"\x03txt\x03rec", 8, wdns_res_success},
	{ "txt \"record\"", WDNS_TYPE_TXT, WDNS_CLASS_IN, (const uint8_t*)"\x03txt\x06record", 11, wdns_res_success},
	{ "txt \"record\" three", WDNS_TYPE_TXT, WDNS_CLASS_IN, (const uint8_t*)"\x03txt\x06record\x05three", 17, wdns_res_success},
	{ "txt \"record\" three\\", WDNS_TYPE_TXT, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0.1", WDNS_TYPE_A, WDNS_CLASS_IN, (const uint8_t*)"\x7f\x00\x00\x01", 4, wdns_res_success},
	{ "127.0.0.256", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "127.0.0.0.1", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "::1", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi", WDNS_TYPE_A, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "305419896 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, (const uint8_t*)"\x12\x34\x56\x78\x7f\x00\xde\xad\xbe\xef\x00", 11, wdns_res_success},
	{ "4294967297 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "-1 127 00deadbeef00", WDNS_TYPE_WKS, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "128 2000::dead:beef fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, (const uint8_t*)"\x80\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\x03""fsi\x02io\x00", 25, wdns_res_success},
	{ "120 2000::dead:be00 fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, (const uint8_t*)"\x78\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\x03""fsi\x02io\x00", 24, wdns_res_success},
	{ "2000::dead:beef fsi.io.", WDNS_TYPE_A6, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "0 ::", WDNS_TYPE_A6, WDNS_CLASS_IN, (const uint8_t*)"\x00\x02::\x00", 5, wdns_res_success},
	{ "0 :: fsi.io", WDNS_TYPE_A6, WDNS_CLASS_IN, (const uint8_t*)"\x00\x02::\x00", 5, wdns_res_success},
	{ "::", WDNS_TYPE_AAAA, WDNS_CLASS_IN, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, wdns_res_success},
	{ "1234:4567::abcd:ef01", WDNS_TYPE_AAAA, WDNS_CLASS_IN, (const uint8_t*)"\x12\x34\x45\x67\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd\xef\x01", 16, wdns_res_success},
	{ "::abcd:ef01", WDNS_TYPE_AAAA, WDNS_CLASS_IN, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd\xef\x01", 16, wdns_res_success},
	{ "", WDNS_TYPE_AAAA, WDNS_CLASS_IN, (const uint8_t*)"", 0, wdns_res_success},
	{ "127.0.0.1", WDNS_TYPE_AAAA, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "fsi.io", WDNS_TYPE_AAAA, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "65535 64 01 ZGVhZGJlZWY=", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, (const uint8_t*)"\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWY==", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, (const uint8_t*)"\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWY", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, (const uint8_t*)"\xff\xff@\x01""deadbeef", 12, wdns_res_success},
	{ "65535 64 01 ZGVhZGJlZWZz", WDNS_TYPE_DNSKEY, WDNS_CLASS_IN, (const uint8_t*)"\xff\xff@\x01""deadbeefs", 13, wdns_res_success},
	{ "fsi.io A NS MX", WDNS_TYPE_NSEC, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00\x00\x02\x60\x01", 12, wdns_res_success},
	{ "fsi.io", WDNS_TYPE_NSEC, WDNS_CLASS_IN, (const uint8_t*)"\x03""fsi\x02io\x00", 8, wdns_res_success},
	{ "fsi.io A NS MX FAKE", WDNS_TYPE_NSEC, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 -", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, (const uint8_t*)"\x01\x02\x00\x03\x00", 5, wdns_res_success},
	{ "1 2 3 deadbeef", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, (const uint8_t*)"\x01\x02\x00\x03\x04\xde\xad\xbe\xef", 9, wdns_res_success},
	{ "1 2 3 deadbeeff", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 deadbeef-", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 gg", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3 --", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, 0, 0, wdns_res_parse_error},
	{ "1 2 3", WDNS_TYPE_NSEC3PARAM, WDNS_CLASS_IN, (const uint8_t*)"\x01\x02\x00\x03", 4, wdns_res_success },
	{ "1 1 10 7225a239d4230bba7be2 O4K23SKVI7PTGVR5LRITC8IDIQ6KJVA0 NS DS RRSIG", WDNS_TYPE_NSEC3, WDNS_CLASS_IN, (const uint8_t*)"\x01\x01\x00\x0a\x0ar%\xa2""9\xd4#\x0b\xba{\xe2\x10\xc1(!\xf2\x9f\x91\xf3\xd8\x7f""e\xae\xe5\xd6\"M\x96\x00\x06 \x00\x00\x00\x00\x12", 40, wdns_res_success },
	{ "NSEC 5 5 7200 1442949945 1440354345 34572 5.in-addr.arpa. aTPqHqvtDsdyY6acy5BzbmjzJcdNWeFW2laTYY/+NJsMAedSryvDJKkA evVh4Fv4G+o9Ts3XKhYUihW2qXp7bbhHmlIvSY3qX67/Ti9DzRPymirt m5ffESFO7+4H2QFd5xIpoJH/WQysNWzCyLt+JeguH4/7PU5C9K30cqqd vJk=", WDNS_TYPE_RRSIG, WDNS_CLASS_IN, (const uint8_t*)"\x00/\x05\x05\x00\x00\x1c V\x01\xab""9U\xda\x10)\x87\x0c\x01""5\x07in-addr\x04""arpa\x00i3\xea\x1e\xab\xed\x0e\xc7rc\xa6\x9c\xcb\x90snh\xf3%\xc7MY\xe1V\xdaV\x93""a\x8f\xfe""4\x9b\x0c\x01\xe7R\xaf+\xc3$\xa9\x00z\xf5""a\xe0[\xf8\x1b\xea=N\xcd\xd7*\x16\x14\x8a\x15\xb6\xa9z{m\xb8G\x9aR/I\x8d\xea_\xae\xffN/C\xcd\x13\xf2\x9a*\xed\x9b\x97\xdf\x11!N\xef\xee\x07\xd9\x01]\xe7\x12)\xa0\x91\xffY\x0c\xac""5l\xc2\xc8\xbb~%\xe8.\x1f\x8f\xfb=NB\xf4\xad\xf4r\xaa\x9d\xbc\x99", 162, wdns_res_success },
	/* generic encodings */
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
test_str_to_rdata(void) {
	ubuf *u;
	struct test *cur;
	size_t failures = 0;

	u = ubuf_init(256);
	assert (u != NULL);

	for(cur = tdata; cur->input != NULL; cur++) {
		uint8_t * actual = NULL;
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

	ret |= check(test_str_to_rdata(), "test_cname");

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
