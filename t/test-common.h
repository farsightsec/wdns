#ifndef TEST_COMMON_H
#define TEST_COMMON_H	1

#include <libmy/ubuf.h>


/* Package a binary data buffer for friendly display */
void escape(ubuf *u, const uint8_t *a, size_t len);

int check(size_t ret, const char *s, const char *cname);

#endif
