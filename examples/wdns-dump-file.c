#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "private.h"

#include <wdns.h>

static int
process_data(const uint8_t *data, size_t len)
{
	wdns_message_t m;
	wdns_res res;

	res = wdns_parse_message(&m, data, len);
	if (res == wdns_res_success) {
		wdns_print_message(stdout, &m);
		wdns_clear_message(&m);
		putchar('\n');
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

int
main(int argc, char **argv) {
	FILE *fp;

	uint8_t data[4096] = {0};
	size_t len;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <INFILE>\n", argv[0]);
		return EXIT_FAILURE;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: unable to open %s: %s\n", argv[1], strerror(errno));
		return EXIT_FAILURE;
	}

	len = fread(data, 1, sizeof(data), fp);
	if (ferror(fp)) {
		fprintf(stderr, "Error: fread() returned an error on %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	if (!feof(fp)) {
		fprintf(stderr, "Error: did not make a complete read of %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	return process_data(data, len);
}
