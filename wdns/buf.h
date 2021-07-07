/*
 * Copyright (c) 2009 by Farsight Security, Inc.
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
