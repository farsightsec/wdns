#include "private.h"

#include <wdns.h>

bool loadfunc(uint8_t *, size_t);
void freefunc(void);
bool testfunc(void);

wdns_rrset_t rrset;

bool
loadfunc(uint8_t *data, size_t len)
{
	wdns_res res;
	res = wdns_deserialize_rrset(&rrset, data, len);
	if (res != wdns_res_success)
		return (false);
	return (true);
}

void
freefunc(void)
{
	wdns_clear_rrset(&rrset);
}

bool
testfunc(void)
{
	wdns_print_rrset(stdout, &rrset, WDNS_MSG_SEC_ANSWER);
	return (true);
}
