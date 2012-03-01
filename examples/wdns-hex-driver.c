#include "private.h"

#include <wdns.h>

extern bool loadfunc(uint8_t *data, size_t len);
extern bool testfunc(void);
extern void freefunc(void);

static bool
hex_to_int(char hex, uint8_t *val)
{
	if (islower((unsigned char) hex))
		hex = toupper((unsigned char) hex);

	switch (hex) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		*val = (hex - '0');
		return (true);
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		*val = (hex - 55);
		return (true);
	default:
		printf("hex_to_int() failed\n");
		return (false);
	}
}

static bool
hex_decode(const char *hex, uint8_t **raw, size_t *len)
{
	size_t hexlen = strlen(hex);
	uint8_t *p;

	if (hexlen == 0 || (hexlen % 2) != 0)
		return (false);

	*len = hexlen / 2;

	p = *raw = malloc(*len);
	if (*raw == NULL)
		return (false);

	while (hexlen != 0) {
		uint8_t val[2];

		if (!hex_to_int(*hex, &val[0]))
			goto err;
		hex++;
		if (!hex_to_int(*hex, &val[1]))
			goto err;
		hex++;

		*p = (val[0] << 4) | val[1];
		p++;

		hexlen -= 2;
	}

	return (true);
err:
	free(*raw);
	return (false);
}

int
main(int argc, char **argv)
{
	size_t rawlen;
	uint8_t *rawdata;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <HEXDATA>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (!hex_decode(argv[1], &rawdata, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	if (loadfunc(rawdata, rawlen)) {
		testfunc();
		freefunc();
	} else {
		free(rawdata);
		fprintf(stderr, "Error: load function failed\n");
		return (EXIT_FAILURE);
	}

	free(rawdata);

	return (EXIT_SUCCESS);
}
