/*
 * Copyright (c) 2012-2015, 2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "wdns.h"

#include "record_descr.h"
#include "libmy/b32_decode.h"
#include "libmy/b32_encode.h"
#include "libmy/b64_decode.h"
#include "libmy/b64_encode.h"

#include "libmy/my_num_to_str.h"

#include "libmy/my_alloc.h"
#include "libmy/ubuf.h"

#include "libmy/fast_inet_ntop.h"

#define load_net16(buf, out) do { \
	uint16_t _my_16; \
	memcpy(&_my_16, buf, sizeof(uint16_t)); \
	_my_16 = ntohs(_my_16); \
	*(out) = _my_16; \
} while (0)

#define load_net32(buf, out) do { \
	uint32_t _my_32; \
	memcpy(&_my_32, buf, sizeof(uint32_t)); \
	_my_32 = ntohl(_my_32); \
	*(out) = _my_32; \
} while (0)

/**
 * Advance pointer p by sz bytes and update len.
 */
#define WDNS_BUF_ADVANCE(p, len, sz) do { \
	p += sz; \
	len -= sz; \
} while (0)

/**
 * Read an 8 bit integer.
 */
#define WDNS_BUF_GET8(dst, src) do { \
	memcpy(&dst, src, 1); \
	src++; \
} while (0)

/**
 * Read a 16 bit integer.
 */
#define WDNS_BUF_GET16(dst, src) do { \
	memcpy(&dst, src, 2); \
	dst = ntohs(dst); \
	src += 2; \
} while (0)

/**
 * Read a 32 bit integer.
 */
#define WDNS_BUF_GET32(dst, src) do { \
	memcpy(&dst, src, 4); \
	dst = ntohl(dst); \
	src += 4; \
} while (0)

wdns_res
_wdns_insert_rr_rrset_array(wdns_rrset_array_t *a, wdns_rr_t *rr, unsigned sec);

wdns_res
_wdns_parse_edns(wdns_message_t *m, wdns_rr_t *rr);

wdns_res
_wdns_parse_rdata(wdns_rr_t *rr, const uint8_t *p, const uint8_t *eop,
		  const uint8_t *rdata, uint16_t rdlen);

wdns_res
_wdns_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
		   uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);

wdns_res
_wdns_parse_message_rr(unsigned sec, const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wdns_rr_t *rr);

void
_wdns_rdata_to_ubuf(ubuf *, const uint8_t *rdata, uint16_t rdlen,
		    uint16_t rrtype, uint16_t rrclass);

wdns_res
_wdns_str_to_rdata_ubuf(ubuf *, const char * str,
		uint16_t rrtype, uint16_t rrclass);

void
_wdns_rr_to_ubuf(ubuf *, wdns_rr_t *rr, unsigned sec);

void
_wdns_rrset_to_ubuf(ubuf *, wdns_rrset_t *rrset, unsigned sec);

void
_wdns_rrset_array_to_ubuf(ubuf *, wdns_rrset_array_t *a, unsigned sec);

uint16_t
_wdns_str_to_svcparamkey(char *str);

char *
_wdns_svcparamkey_to_str(uint16_t key, char *buf, size_t len);

void
_wdns_ednsoptcode_to_ubuf(ubuf *, uint16_t option_code);

wdns_res
_wdns_ednsoptdata_to_ubuf(ubuf *u, uint16_t option_code, const uint8_t *src, uint16_t src_bytes);
