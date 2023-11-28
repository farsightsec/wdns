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


static void
print_data(const uint8_t *d, size_t len) {
        while (len-- != 0)
                fprintf(stderr, "%02x", *(d++));
        fprintf(stderr, "\n");
}

bool
testfunc(void)
{
	wdns_rrset_array_t *a;
	wdns_rrset_t *rrset;
	size_t n, sz, sec;
	uint8_t *buf;

	for (sec = WDNS_MSG_SEC_ANSWER; sec < WDNS_MSG_SEC_MAX; sec++) {
		a = &m.sections[sec];
		for (n = 0; n < a->n_rrsets; n++) {
			rrset = &a->rrsets[n];
			wdns_serialize_rrset(rrset, NULL, &sz);
			buf = alloca(sz);
			wdns_serialize_rrset(rrset, buf, NULL);
			print_data(buf, sz);
		}
	}
	return (true);
}
