#include <libmy/ubuf.h>
#include "private.h"
#include "../wdns/wdns.h"

VECTOR_GENERATE(u16buf, uint16_t)

static int
cmp_u16(const void *a, const void *b) {
	uint16_t u1 = *(uint16_t *)a;
	uint16_t u2 = *(uint16_t *)b;
	return u1 == u2 ? 0 : u1 > u2 ? 1 : -1;
}


int
main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s \"<space separated RRtypes>\"\n", argv[0]);
		return (EXIT_FAILURE);
	}

	const char *input_rrtypes = argv[1];

	const char *end;
	char *s_rrtype;
	u16buf *rrtypes;
	uint16_t my_rrtype, last_rrtype;
	size_t n;
	uint8_t window_block, bitmap_len;
	uint8_t bitmap[32];

	rrtypes = u16buf_init(16);
	if (! rrtypes) {
		printf("malloc failed\n");
		return (EXIT_FAILURE);
	}

	while (input_rrtypes != NULL && *input_rrtypes) {
		if (isspace(*input_rrtypes)) {
			input_rrtypes++;
			continue;
		}

		end = strpbrk(input_rrtypes, " \t\r\n");
		if (end != NULL) {
			s_rrtype = strndup(input_rrtypes, end-input_rrtypes);
		} else {
			s_rrtype = strdup(input_rrtypes);
		}

		my_rrtype = wdns_str_to_rrtype(s_rrtype);

		if (my_rrtype == 0) {
			printf("Failed to parse %s as an rrtype\n", s_rrtype);
			free(s_rrtype);
			u16buf_destroy(&rrtypes);
			return (EXIT_FAILURE);
		}
		free(s_rrtype);

		u16buf_add(rrtypes, my_rrtype);
		input_rrtypes = end;
	}
	if (u16buf_size(rrtypes) == 0) {
		printf("Failure: No RRtypes were parsed\n");
		return (EXIT_FAILURE);
	}


	qsort(u16buf_data(rrtypes), u16buf_size(rrtypes), sizeof(uint16_t), cmp_u16);

	memset(bitmap, 0, sizeof(bitmap));
	window_block = 0;
	bitmap_len = 0;
	last_rrtype = 0;

	ubuf *u_result;
	u_result = ubuf_new();

	for (n = 0; n < u16buf_size(rrtypes); n++) {
		my_rrtype = u16buf_value(rrtypes, n);
		if (my_rrtype == last_rrtype) {
			continue;
		}
		last_rrtype = my_rrtype;

		uint8_t cur_window = my_rrtype / 256;

		if (cur_window != window_block) {
			ubuf_append(u_result, (const uint8_t*)&window_block, sizeof(window_block));
			ubuf_append(u_result, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
			ubuf_append(u_result, (const uint8_t*)bitmap, bitmap_len);
			memset(bitmap, 0, sizeof(bitmap));
			window_block = cur_window;
		}

		uint8_t offset = my_rrtype % 256;
		uint8_t byte = offset / 8;
		uint8_t bit = offset % 8;

		bitmap[byte] |= 0x80 >> bit;
		bitmap_len = 1 + byte;
	}
	ubuf_append(u_result, (const uint8_t*)&window_block, sizeof(window_block));
	ubuf_append(u_result, (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
	ubuf_append(u_result, (const uint8_t*)bitmap, bitmap_len);

	u16buf_destroy(&rrtypes);

	printf("bitmap: ");
	for (n = 0; n < ubuf_size(u_result); n++) {
		printf("%02x ", (unsigned char)ubuf_value(u_result, n));
	}
	printf("\n");
	return 0;
}
