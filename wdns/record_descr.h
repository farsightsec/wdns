/*
 * Copyright (c) 2009-2010, 2012, 2016, 2021 by Farsight Security, Inc.
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

#ifndef WDNS_RECORD_DESCR_H
#define WDNS_RECORD_DESCR_H

#include <stdint.h>

typedef enum {
	class_un,	/* not class specific */
	class_in	/* Internet class */
} record_class;

typedef enum {
	rdf_unknown,	/* marker for unpopulated entries */
	rdf_bytes,	/* byte array (terminal) */
	rdf_bytes_b64,	/* byte array (terminal) (base64 encoded presentation) */
	rdf_bytes_str,	/* byte array (terminal) (string representation) */
	rdf_name,	/* series of labels terminated by zero-length label, possibly compressed */
	rdf_uname,	/* series of labels terminated by zero-length label, NOT compressed */
	rdf_int8,	/* 8 bit integer */
	rdf_int16,	/* 16 bit integer */
	rdf_int32,	/* 32 bit integer */
	rdf_ipv4,	/* IPv4 host address */
	rdf_ipv6,	/* IPv6 host address */
	rdf_ipv6prefix,	/* IPv6 prefix: length octet followed by 0-16 octets */
	rdf_eui48,	/* EUI-48 address */
	rdf_eui64,	/* EUI-64 address */
	rdf_string,	/* length octet followed by that many octets */
	rdf_repstring,	/* one or more strings (terminal) */
	rdf_rrtype,	/* resource record type */
	rdf_type_bitmap,/* rr type bitmap */
	rdf_salt,	/* length-prefixed salt value (hex presentation) */
	rdf_hash,	/* length-prefixed hash value (base32 presentation) */
	rdf_svcparams,	/* list of space separated key=value pairs */
	rdf_end,	/* sentinel (terminal) */
} rdf_type;

typedef struct {
	uint16_t	record_class;
	uint8_t		types[10];
} record_descr;

extern const record_descr	record_descr_array[];
extern const size_t		record_descr_len;

/*
 * Service Binding (SVCB) Parameter Registry
 */
typedef enum {
	spr_mandatory = 0,

	/*
	 * The "alpn" and "no-default-alpn" SvcParamKeys together indicate the
	 * set of Application Layer Protocol Negotiation (ALPN) protocol
	 * identifiers [ALPN] and associated transport protocols supported by
	 * this service endpoint.
	 */
	spr_alpn = 1,
	spr_nd_alpn = 2,

	/*
	 * TCP or UDP port that should be used to reach this alternative
	 * endpoint. If this key is not present, clients SHALL use the
	 * authority endpoint's port number.
	 */
	spr_port = 3,

	/* Encrypted ClientHello info */
	spr_echconfig = 5,

	/*
	 * The "hint" keys convey IP addresses that clients MAY use to reach
	 * the service.
	 */
	spr_ipv4hint = 4,
	spr_ipv6hint = 6,

	/* Reserved ("Invalid Key") */
	spr_invalid = 65535,

} svcb_svcparam_keys;

#endif /* WDNS_RECORD_DESCR_H */
