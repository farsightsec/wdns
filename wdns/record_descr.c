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
};

const size_t record_descr_len = sizeof(record_descr_array) / sizeof(record_descr);
