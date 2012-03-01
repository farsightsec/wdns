#include "private.h"

#include <wdns.h>

bool loadfunc(uint8_t *, size_t);
void freefunc(void);
bool testfunc(void);

wdns_message_t m;

bool
loadfunc(uint8_t *data, size_t len)
{
	wdns_res res;
	res = wdns_parse_message(&m, data, len);
	if (res != wdns_res_success)
		return (false);
	return (true);
}

void
freefunc(void)
{
	wdns_clear_message(&m);
}

bool
testfunc(void)
{
	wdns_print_message(stdout, &m);
	return (true);
}
