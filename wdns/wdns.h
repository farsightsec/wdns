/*
 * Copyright (c) 2009-2013 by Farsight Security, Inc.
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

#ifndef WDNS_H
#define WDNS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Constants. */

#define WDNS_LEN_HEADER		12
#define WDNS_MAXLEN_NAME	255

#define WDNS_MSG_SEC_QUESTION	0
#define WDNS_MSG_SEC_ANSWER	1
#define WDNS_MSG_SEC_AUTHORITY	2
#define WDNS_MSG_SEC_ADDITIONAL	3
#define WDNS_MSG_SEC_MAX	4

#define WDNS_PRESLEN_NAME	1025
#define WDNS_PRESLEN_TYPE_A	16
#define WDNS_PRESLEN_TYPE_AAAA	46

#define WDNS_OP_QUERY		0
#define WDNS_OP_IQUERY		1
#define WDNS_OP_STATUS		2
#define WDNS_OP_NOTIFY		4
#define WDNS_OP_UPDATE		5

#define WDNS_R_NOERROR		0
#define WDNS_R_FORMERR		1
#define WDNS_R_SERVFAIL		2
#define WDNS_R_NXDOMAIN		3
#define WDNS_R_NOTIMP		4
#define WDNS_R_REFUSED		5
#define WDNS_R_YXDOMAIN		6
#define WDNS_R_YXRRSET		7
#define WDNS_R_NXRRSET		8
#define WDNS_R_NOTAUTH		9
#define WDNS_R_NOTZONE		10
#define WDNS_R_BADVERS		16

#define WDNS_CLASS_IN		1
#define WDNS_CLASS_CH		3
#define WDNS_CLASS_HS		4
#define WDNS_CLASS_NONE		254
#define WDNS_CLASS_ANY		255

#define WDNS_TYPE_A		1
#define WDNS_TYPE_NS		2
#define WDNS_TYPE_MD		3
#define WDNS_TYPE_MF		4
#define WDNS_TYPE_CNAME		5
#define WDNS_TYPE_SOA		6
#define WDNS_TYPE_MB		7
#define WDNS_TYPE_MG		8
#define WDNS_TYPE_MR		9
#define WDNS_TYPE_NULL		10
#define WDNS_TYPE_WKS		11
#define WDNS_TYPE_PTR		12
#define WDNS_TYPE_HINFO		13
#define WDNS_TYPE_MINFO		14
#define WDNS_TYPE_MX		15
#define WDNS_TYPE_TXT		16
#define WDNS_TYPE_RP		17
#define WDNS_TYPE_AFSDB		18
#define WDNS_TYPE_X25		19
#define WDNS_TYPE_ISDN		20
#define WDNS_TYPE_RT		21
#define WDNS_TYPE_NSAP		22
#define WDNS_TYPE_NSAP_PTR	23
#define WDNS_TYPE_SIG		24
#define WDNS_TYPE_KEY		25
#define WDNS_TYPE_PX		26
#define WDNS_TYPE_GPOS		27
#define WDNS_TYPE_AAAA		28
#define WDNS_TYPE_LOC		29
#define WDNS_TYPE_NXT		30
#define WDNS_TYPE_EID		31
#define WDNS_TYPE_NIMLOC	32
#define WDNS_TYPE_SRV		33
#define WDNS_TYPE_ATMA		34
#define WDNS_TYPE_NAPTR		35
#define WDNS_TYPE_KX		36
#define WDNS_TYPE_CERT		37
#define WDNS_TYPE_A6		38
#define WDNS_TYPE_DNAME		39
#define WDNS_TYPE_SINK		40
#define WDNS_TYPE_OPT		41
#define WDNS_TYPE_APL		42
#define WDNS_TYPE_DS		43
#define WDNS_TYPE_SSHFP		44
#define WDNS_TYPE_IPSECKEY	45
#define WDNS_TYPE_RRSIG		46
#define WDNS_TYPE_NSEC		47
#define WDNS_TYPE_DNSKEY	48
#define WDNS_TYPE_DHCID		49
#define WDNS_TYPE_NSEC3		50
#define WDNS_TYPE_NSEC3PARAM	51
#define WDNS_TYPE_TLSA		52
/* Unassigned: 53 - 54 */
#define WDNS_TYPE_HIP		55
#define WDNS_TYPE_NINFO		56
#define WDNS_TYPE_RKEY		57
#define WDNS_TYPE_TALINK	58
#define WDNS_TYPE_CDS		59
#define WDNS_TYPE_CDNSKEY	60
#define WDNS_TYPE_OPENPGPKEY	61
#define WDNS_TYPE_CSYNC		62
/* Unassigned: 63 - 98 */
#define WDNS_TYPE_SPF		99
#define WDNS_TYPE_UINFO		100
#define WDNS_TYPE_UID		101
#define WDNS_TYPE_GID		102
#define WDNS_TYPE_UNSPEC	103
#define WDNS_TYPE_NID		104
#define WDNS_TYPE_L32		105
#define WDNS_TYPE_L64		106
#define WDNS_TYPE_LP		107
#define WDNS_TYPE_EUI48		108
#define WDNS_TYPE_EUI64		109
/* Unassigned: 110 - 248 */
#define WDNS_TYPE_TKEY		249
#define WDNS_TYPE_TSIG		250
#define WDNS_TYPE_IXFR		251
#define WDNS_TYPE_AXFR		252
#define WDNS_TYPE_MAILB		253
#define WDNS_TYPE_MAILA		254
#define WDNS_TYPE_ANY		255
#define WDNS_TYPE_URI		256
#define WDNS_TYPE_CAA		257
/* Unassigned: 258 - 32767 */
#define WDNS_TYPE_TA		32768
#define WDNS_TYPE_DLV		32769
/* Unassigned: 32770 - 65279 */
/* Private use: 65280 - 65534 */
/* Reserved: 65535 */

/* Macros. */

#define WDNS_FLAGS_QR(msg)		((((msg).flags) >> 15) & 0x01)
#define WDNS_FLAGS_OPCODE(msg)		((((msg).flags) >> 11) & 0x0f)
#define WDNS_FLAGS_AA(msg)		((((msg).flags) >> 10) & 0x01)
#define WDNS_FLAGS_TC(msg)		((((msg).flags) >> 9) & 0x01)
#define WDNS_FLAGS_RD(msg)		((((msg).flags) >> 8) & 0x01)
#define WDNS_FLAGS_RA(msg)		((((msg).flags) >> 7) & 0x01)
#define WDNS_FLAGS_Z(msg)		((((msg).flags) >> 6) & 0x01)
#define WDNS_FLAGS_AD(msg)		((((msg).flags) >> 5) & 0x01)
#define WDNS_FLAGS_CD(msg)		((((msg).flags) >> 4) & 0x01)
#define WDNS_FLAGS_RCODE(msg)		((msg).rcode)

#if defined(__GNUC__)
# define WDNS_WARN_UNUSED_RESULT	__attribute__ ((warn_unused_result))
#else
# define WDNS_WARN_UNUSED_RESULT
#endif

/* Data structures and definitions. */

typedef enum {
	wdns_res_success,
	wdns_res_failure,
	wdns_res_invalid_compression_pointer,
	wdns_res_invalid_length_octet,
	wdns_res_invalid_opcode,
	wdns_res_invalid_rcode,
	wdns_res_len,
	wdns_res_malloc,
	wdns_res_name_len,
	wdns_res_name_overflow,
	wdns_res_out_of_bounds,
	wdns_res_overflow,
	wdns_res_parse_error,
	wdns_res_qdcount,
	wdns_res_unknown_opcode,
	wdns_res_unknown_rcode,
} wdns_res;

typedef struct {
	uint8_t			len;
	uint8_t			*data;
} wdns_name_t;

typedef struct {
	uint16_t		len;
	uint8_t			data[];
} wdns_rdata_t;

typedef struct {
	uint32_t		rrttl;
	uint16_t		rrtype;
	uint16_t		rrclass;
	wdns_name_t		name;
	wdns_rdata_t		*rdata;
} wdns_rr_t;

typedef struct {
	uint32_t		rrttl;
	uint16_t		rrtype;
	uint16_t		rrclass;
	uint16_t		n_rdatas;
	wdns_name_t		name;
	wdns_rdata_t		**rdatas;
} wdns_rrset_t;

typedef struct {
	uint16_t		n_rrs;
	uint16_t		n_rrsets;
	wdns_rr_t		*rrs;
	wdns_rrset_t		*rrsets;
} wdns_rrset_array_t;

typedef struct {
	bool			present;
	uint8_t			version;
	uint16_t		flags;
	uint16_t		size;
	wdns_rdata_t		*options;
} wdns_edns_t;

typedef struct {
	wdns_rrset_array_t	sections[4];
	wdns_edns_t		edns;
	uint16_t		id;
	uint16_t		flags;
	uint16_t		rcode;
} wdns_message_t;

/* Function prototypes. */

typedef void (*wdns_callback_name)(wdns_name_t *name, void *user);

/* Functions for converting objects to presentation format strings. */

const char *	wdns_res_to_str(wdns_res res);
const char *	wdns_opcode_to_str(uint16_t dns_opcode);
const char *	wdns_rcode_to_str(uint16_t dns_rcode);
const char *	wdns_rrclass_to_str(uint16_t dns_class);
const char *	wdns_rrtype_to_str(uint16_t dns_type);
size_t		wdns_domain_to_str(const uint8_t *src, size_t src_len, char *dst);

char *		wdns_message_to_str(wdns_message_t *m);
char *		wdns_rrset_array_to_str(wdns_rrset_array_t *a, unsigned sec);
char *		wdns_rrset_to_str(wdns_rrset_t *rrset, unsigned sec);
char *		wdns_rr_to_str(wdns_rr_t *rr, unsigned sec);
char *		wdns_rdata_to_str(const uint8_t *rdata, uint16_t rdlen,
				  uint16_t rrtype, uint16_t rrclass);

/* Functions for converting presentation format strings to objects. */

WDNS_WARN_UNUSED_RESULT
wdns_res
wdns_str_to_name(const char *str, wdns_name_t *name);

WDNS_WARN_UNUSED_RESULT
wdns_res
wdns_str_to_name_case(const char *str, wdns_name_t *name);

wdns_res
wdns_str_to_rcode(const char *str, uint16_t *out);

uint16_t
wdns_str_to_rrtype(const char *str);

uint16_t
wdns_str_to_rrclass(const char *str);

wdns_res
wdns_str_to_rdata(const char * str, uint16_t rrtype, uint16_t rrclass,
		   uint8_t **rdata, size_t *rdlen);

/* Comparison functions. */

bool	wdns_compare_rr_rrset(const wdns_rr_t *rr, const wdns_rrset_t *rrset);

/* Functions for clearing wdns objects. */

void	wdns_clear_message(wdns_message_t *m);
void	wdns_clear_rr(wdns_rr_t *rr);
void	wdns_clear_rrset(wdns_rrset_t *rrset);
void	wdns_clear_rrset_array(wdns_rrset_array_t *a);

/* Functions for printing formatted output. */

void	wdns_print_message(FILE *fp, wdns_message_t *m);
void	wdns_print_rr(FILE *fp, wdns_rr_t *rr, unsigned sec);
void	wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset, unsigned sec);
void	wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *a, unsigned sec);

/* Utility functions. */

size_t	wdns_skip_name(const uint8_t **data, const uint8_t *eod);

wdns_res
wdns_copy_uname(const uint8_t *p, const uint8_t *eop, const uint8_t *src,
		uint8_t *dst, size_t *sz);

wdns_res
wdns_len_uname(const uint8_t *p, const uint8_t *eop, size_t *sz);

wdns_res
wdns_sort_rrset(wdns_rrset_t *);

wdns_res
wdns_unpack_name(const uint8_t *p, const uint8_t *eop, const uint8_t *src,
		 uint8_t *dst, size_t *sz);

wdns_res
wdns_count_labels(wdns_name_t *name, size_t *nlabels);

wdns_res
wdns_is_subdomain(wdns_name_t *n0, wdns_name_t *n1, bool *is_subdomain);

wdns_res
wdns_file_load_names(const char *fname, wdns_callback_name cb, void *user);

wdns_res
wdns_left_chop(wdns_name_t *name, wdns_name_t *chop);

WDNS_WARN_UNUSED_RESULT
wdns_res
wdns_reverse_name(const uint8_t *name, size_t len_name, uint8_t *rev_name);

/* Parsing functions. */

wdns_res
wdns_parse_message(wdns_message_t *m, const uint8_t *pkt, size_t len);

/* Deserialization functions. */

wdns_res
wdns_deserialize_rrset(wdns_rrset_t *rrset, const uint8_t *buf, size_t sz);

/* Serialization functions. */

wdns_res
wdns_serialize_rrset(const wdns_rrset_t *rrset, uint8_t *buf, size_t *sz);

/* Downcasing functions. */

void
wdns_downcase_name(wdns_name_t *name);

wdns_res
wdns_downcase_rdata(wdns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass);

wdns_res
wdns_downcase_rrset(wdns_rrset_t *rrset);

#ifdef __cplusplus
}
#endif

#endif /* WDNS_H */
