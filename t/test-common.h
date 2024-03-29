/*
 * Copyright (c) 2022 DomainTools LLC
 * Copyright (c) 2018, 2021 by Farsight Security, Inc.
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

#ifndef TEST_COMMON_H
#define TEST_COMMON_H	1

#include <libmy/ubuf.h>

#define	QUOTE(...)	#__VA_ARGS__

/* Package a binary data buffer for friendly display */
void escape(ubuf *u, const uint8_t *a, size_t len);

int check(size_t ret, const char *s, const char *cname);

#endif
