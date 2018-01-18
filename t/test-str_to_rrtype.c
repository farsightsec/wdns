#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "test-common.h"

#include <libmy/ubuf.h>
#include <wdns.h>

#define NAME "test-str_to_rrtype"

static struct u16str {
    uint16_t u16;
    const char *str;
} rrtypes[] = {
	{ WDNS_TYPE_A, "A" },
	{ WDNS_TYPE_A6, "A6" },
	{ WDNS_TYPE_AAAA, "AAAA" },
	{ WDNS_TYPE_AFSDB, "AFSDB" },
	{ WDNS_TYPE_ANY, "ANY" },
	{ WDNS_TYPE_APL, "APL" },
	{ WDNS_TYPE_ATMA, "ATMA" },
	{ WDNS_TYPE_AXFR, "AXFR" },
	{ WDNS_TYPE_CAA, "CAA" },
	{ WDNS_TYPE_CDNSKEY, "CDNSKEY" },
	{ WDNS_TYPE_CDS, "CDS" },
	{ WDNS_TYPE_CERT, "CERT" },
	{ WDNS_TYPE_CNAME, "CNAME" },
	{ WDNS_TYPE_CSYNC, "CSYNC" },
	{ WDNS_TYPE_DHCID, "DHCID" },
	{ WDNS_TYPE_DLV, "DLV" },
	{ WDNS_TYPE_DNAME, "DNAME" },
	{ WDNS_TYPE_DNSKEY, "DNSKEY" },
	{ WDNS_TYPE_DS, "DS" },
	{ WDNS_TYPE_EID, "EID" },
	{ WDNS_TYPE_EUI48, "EUI48" },
	{ WDNS_TYPE_EUI64, "EUI64" },
	{ WDNS_TYPE_GID, "GID" },
	{ WDNS_TYPE_GPOS, "GPOS" },
	{ WDNS_TYPE_HINFO, "HINFO" },
	{ WDNS_TYPE_HIP, "HIP" },
	{ WDNS_TYPE_IPSECKEY, "IPSECKEY" },
	{ WDNS_TYPE_ISDN, "ISDN" },
	{ WDNS_TYPE_IXFR, "IXFR" },
	{ WDNS_TYPE_KEY, "KEY" },
	{ WDNS_TYPE_KX, "KX" },
	{ WDNS_TYPE_L32, "L32" },
	{ WDNS_TYPE_L64, "L64" },
	{ WDNS_TYPE_LOC, "LOC" },
	{ WDNS_TYPE_LP, "LP" },
	{ WDNS_TYPE_MAILA, "MAILA" },
	{ WDNS_TYPE_MAILB, "MAILB" },
	{ WDNS_TYPE_MB, "MB" },
	{ WDNS_TYPE_MD, "MD" },
	{ WDNS_TYPE_MF, "MF" },
	{ WDNS_TYPE_MG, "MG" },
	{ WDNS_TYPE_MINFO, "MINFO" },
	{ WDNS_TYPE_MR, "MR" },
	{ WDNS_TYPE_MX, "MX" },
	{ WDNS_TYPE_NAPTR, "NAPTR" },
	{ WDNS_TYPE_NID, "NID" },
	{ WDNS_TYPE_NIMLOC, "NIMLOC" },
	{ WDNS_TYPE_NINFO, "NINFO" },
	{ WDNS_TYPE_NS, "NS" },
	{ WDNS_TYPE_NSAP, "NSAP" },
	{ WDNS_TYPE_NSAP_PTR, "NSAP-PTR" },
	{ WDNS_TYPE_NSEC, "NSEC" },
	{ WDNS_TYPE_NSEC3, "NSEC3" },
	{ WDNS_TYPE_NSEC3PARAM, "NSEC3PARAM" },
	{ WDNS_TYPE_NULL, "NULL" },
	{ WDNS_TYPE_NXT, "NXT" },
	{ WDNS_TYPE_OPENPGPKEY, "OPENPGPKEY" },
	{ WDNS_TYPE_OPT, "OPT" },
	{ WDNS_TYPE_PTR, "PTR" },
	{ WDNS_TYPE_PX, "PX" },
	{ WDNS_TYPE_RKEY, "RKEY" },
	{ WDNS_TYPE_RP, "RP" },
	{ WDNS_TYPE_RRSIG, "RRSIG" },
	{ WDNS_TYPE_RT, "RT" },
	{ WDNS_TYPE_SIG, "SIG" },
	{ WDNS_TYPE_SINK, "SINK" },
	{ WDNS_TYPE_SOA, "SOA" },
	{ WDNS_TYPE_SPF, "SPF" },
	{ WDNS_TYPE_SRV, "SRV" },
	{ WDNS_TYPE_SSHFP, "SSHFP" },
	{ WDNS_TYPE_TA, "TA" },
	{ WDNS_TYPE_TALINK, "TALINK" },
	{ WDNS_TYPE_TKEY, "TKEY" },
	{ WDNS_TYPE_TLSA, "TLSA" },
	{ WDNS_TYPE_TSIG, "TSIG" },
	{ WDNS_TYPE_TXT, "TXT" },
	{ WDNS_TYPE_UID, "UID" },
	{ WDNS_TYPE_UINFO, "UINFO" },
	{ WDNS_TYPE_UNSPEC, "UNSPEC" },
	{ WDNS_TYPE_URI, "URI" },
	{ WDNS_TYPE_WKS, "WKS" },
	{ WDNS_TYPE_X25, "X25" },
};

#define num_rrtypes (sizeof(rrtypes) / sizeof(struct u16str))

static size_t
test_str_to_rrtype(void) {
	size_t n;
	size_t failures = 0;

	for(n = 0; n < num_rrtypes; n++) {
		uint16_t rrtype;
		rrtype = wdns_str_to_rrtype(rrtypes[n].str);
		if (rrtype != rrtypes[n].u16) {
			fprintf (stderr, "FAIL: %s %d != %d\n", rrtypes[n].str, rrtype, rrtypes[n].u16);
			failures++;
		} else {
			fprintf (stderr, "PASS: %s = %d\n", rrtypes[n].str, rrtype);
		}
	}

	return failures;
}

int main (int argc, char **argv) {
	int ret = 0;

	ret |= check(test_str_to_rrtype(), "test_cname", NAME);

	if (ret)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
