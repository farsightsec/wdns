/*
 * Copyright (c) 2022 DomainTools LLC
 * Copyright (c) 2009-2012, 2015-2016, 2021 by Farsight Security, Inc.
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

#include "record_descr.h"

const record_descr record_descr_array[] = {
	/* RFC 1035 class insensitive well-known types */

	[WDNS_TYPE_CNAME] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_HINFO] =
		{ class_un, { rdf_string, rdf_string, rdf_end } },

	[WDNS_TYPE_MB] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MD] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MF] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MG] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MINFO] =
		{ class_un, { rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_MR] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MX] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_NS] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_NULL] =
		{ class_un, { rdf_bytes, rdf_end } },

	[WDNS_TYPE_PTR] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_SOA] =
		{ class_un, { rdf_name, rdf_name, rdf_int32, rdf_int32, rdf_int32,
				rdf_int32, rdf_int32, rdf_end } },

	[WDNS_TYPE_TXT] =
		{ class_un, { rdf_repstring, rdf_end } },

	/* RFC 1035 Internet class well-known types */

	[WDNS_TYPE_A] =
		{ class_in, { rdf_ipv4, rdf_end } },

	[WDNS_TYPE_WKS] =
		{ class_in, { rdf_int32, rdf_int8, rdf_bytes, rdf_end } },

	/* post-RFC 1035 class insensitive types */

	[WDNS_TYPE_AFSDB] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_ISDN] =
		{ class_un, { rdf_string, rdf_string, rdf_end } },

	[WDNS_TYPE_RP] =
		{ class_un, { rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_RT] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_X25] =
		{ class_un, { rdf_string, rdf_end } },

	[WDNS_TYPE_NXT] =
		{ class_un, { rdf_name, rdf_bytes, rdf_end } },

	[WDNS_TYPE_SIG] =
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_int32, rdf_int32, rdf_int32,
				rdf_int16, rdf_name, rdf_bytes, rdf_end } },

	[WDNS_TYPE_DNAME] =
		{ class_un, { rdf_uname, rdf_end } },

	/* post-RFC 1035 Internet class types */

	[WDNS_TYPE_A6] =
		{ class_in, { rdf_ipv6prefix, rdf_uname, rdf_end } },

	[WDNS_TYPE_AAAA] =
		{ class_in, { rdf_ipv6, rdf_end } },

	[WDNS_TYPE_KX] =
		{ class_in, { rdf_int16, rdf_uname, rdf_end } },

	[WDNS_TYPE_PX] =
		{ class_in, { rdf_int16, rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_NAPTR] =
		{ class_in, { rdf_int16, rdf_int16, rdf_string, rdf_string, rdf_string,
				rdf_name, rdf_end } },

	[WDNS_TYPE_SRV] =
		{ class_in, { rdf_int16, rdf_int16, rdf_int16, rdf_name, rdf_end } },

	/* RFC 4034 DNSSEC types */

	[WDNS_TYPE_DNSKEY] =
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_bytes_b64, rdf_end } },
			/* flags, protocol, algorithm, public key */

	[WDNS_TYPE_RRSIG] =
		{ class_un, { rdf_rrtype, rdf_int8, rdf_int8, rdf_int32, rdf_int32, rdf_int32,
				    rdf_int16, rdf_uname, rdf_bytes_b64, rdf_end } },
			/* rrtype covered, algorithm, labels, original TTL,
			 * signature expiration, signature inception, key tag, signer's name,
			 * signature */

	[WDNS_TYPE_NSEC] =
		{ class_un, { rdf_uname, rdf_type_bitmap, rdf_end } },
			/* next domain name, rrtype bit maps */

	[WDNS_TYPE_DS] =
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_bytes, rdf_end } },
			/* key tag, algorithm, digest type, digest */

	/* RFC 5155 DNSSEC types */

	[WDNS_TYPE_NSEC3] =
		{ class_un, { rdf_int8, rdf_int8, rdf_int16, rdf_salt, rdf_hash,
				    rdf_type_bitmap, rdf_end } },
			/* hash algorithm, flags, iterations, salt, hash, rrtype bit maps */

	[WDNS_TYPE_NSEC3PARAM] =
		{ class_un, { rdf_int8, rdf_int8, rdf_int16, rdf_salt, rdf_end } },
			/* hash algorithm, flags, iterations, salt */

	/* RFC 4408 */

	[WDNS_TYPE_SPF] =
		{ class_un, { rdf_repstring, rdf_end } },

	/* RFC 6698 */

	[WDNS_TYPE_TLSA] = {
		class_un,
		{
			rdf_int8,	/* Certificate Usage */
			rdf_int8,	/* Selector */
			rdf_int8,	/* Matching Type */
			rdf_bytes,	/* Certificate Association Data */
			rdf_end,
		}
	},

	/* RFC 7344 */

	[WDNS_TYPE_CDNSKEY] =	/* Same as DNSKEY */
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_bytes_b64, rdf_end } },

	[WDNS_TYPE_CDS] =	/* Same as DS */
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_bytes, rdf_end } },

	/* draft-ietf-dane-openpgpkey-06 */

	[WDNS_TYPE_OPENPGPKEY] = {
		class_un,
		{
			rdf_bytes_b64,	/* OpenPGP Transferable Public Key */
			rdf_end,
		}
	},

	/* RFC 7477 */

	[WDNS_TYPE_CSYNC] = {
		class_un,
		{
			rdf_int32,	/* SOA Serial */
			rdf_int16,	/* Flags */
			rdf_type_bitmap,/* Type Bit Map */
			rdf_end,
		}
	},

	/* RFC 7043 */

	[WDNS_TYPE_EUI48] = {
		class_un,
		{
			rdf_eui48,	/* Address */
			rdf_end,
		}
	},

	[WDNS_TYPE_EUI64] = {
		class_un,
		{
			rdf_eui64,	/* Address */
			rdf_end,
		}
	},

	/* RFC 7553 */

	[WDNS_TYPE_URI] = {
		class_un,
		{
			rdf_int16,	/* Priority */
			rdf_int16,	/* Weight */
			rdf_bytes_str,	/* Target */
			rdf_end,
		}
	},

	/* draft-ietf-dnsop-svcb-https-08 */
	[WDNS_TYPE_SVCB] = {	/* used to locate alt endpoints for a service */
		class_in,
		{
			rdf_int16,	/* SvcPriority: The priority of this
					   record (relative to others, with
					   lower values preferred). A value of
					   0 indicates AliasMode */
			rdf_name,	/* TargetName: The domain name of either
					   the alias target (for AliasMode) or
					   the alternative endpoint (for
					   ServiceMode) */
			rdf_svcparams,	/* SvcParams (optional): A list of
					   key=value pairs describing the
					   alternative endpoint at TargetName
					   (only used in ServiceMode and
					   otherwise ignored). */
			rdf_end,
		}
	},

	/* draft-ietf-dnsop-svcb-https-08 */
	[WDNS_TYPE_HTTPS] = {	/* a SVCB-compatible RR type for HTTPS */
		class_in,
		{
			rdf_int16,	/* SvcFieldPriority*/
			rdf_name,	/* SvcDomainName*/
			rdf_svcparams,	/* SvcFieldValue */
			rdf_end,
		}
	},

	[WDNS_TYPE_CAA] = {
		class_in,
		{
			rdf_int8,	/* flags: an unsigned int [0..255] */
			rdf_string,	/* tag: length byte plus a sequence of
					   ASCII letters and numbers limited
					   to [a..z], [A..Z] and [0..9]. Note
					   that we don't enforce these range
					   limitations. */
			rdf_bytes_str,	/* value: either (1) a contiguous set
					   of characters without interior
					   spaces or (2) a quoted string per
					   section 5.1 of rfc1035. It contains
					   no length byte and is not limited
					   to 255 chars */
			rdf_end,
		}
	},

	[WDNS_TYPE_OPT] = {
		class_un,
		{
			rdf_edns_opt_rdata,
			rdf_end,
		}
	},

};

const size_t record_descr_len = sizeof(record_descr_array) / sizeof(record_descr);
