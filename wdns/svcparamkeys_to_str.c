/*
 * Copyright (c) 2021 Farsight Security, Inc.
 *
 * Helper routines for values in the Service Binding (SVCB) Parameter Registry.
 */
char *
_wdns_svcparamkey_to_str(uint16_t key, char *buf, size_t len)
{
	switch (key) {
	case spr_mandatory:
		return (strncpy(buf, "mandatory", len));

	case spr_alpn:
		return (strncpy(buf, "alpn", len));

	case spr_nd_alpn:
		return (strncpy(buf, "no-default-alpn", len));

	case spr_port:
		return (strncpy(buf, "port", len));

	case spr_echconfig:
		return (strncpy(buf, "echconfig", len));

	case spr_ipv4hint:
		return (strncpy(buf, "ipv4hint", len));

	case spr_ipv6hint:
		return (strncpy(buf, "ipv6hint", len));

	case spr_invalid:
		return (strncpy(buf, "invalid key", len));

	default:
		if (snprintf(buf, len, "key%hu", key) > 0) {
			return (buf);
		}
	}

	return (NULL);
}

uint16_t
_wdns_str_to_svcparamkey(char *str)
{
	if (strcmp(str, "mandatory") == 0) {
		return (spr_mandatory);
	} else if (strcmp(str, "alpn") == 0) {
		return (spr_alpn);
	} else if (strcmp(str, "no-default-alpn") == 0) {
		return (spr_nd_alpn);
	} else if (strcmp(str, "port") == 0) {
		return (spr_port);
	} else if (strcmp(str, "echconfig") == 0) {
		return (spr_echconfig);
	} else if (strcmp(str, "ipv4hint") == 0) {
		return (spr_ipv4hint);
	} else if (strcmp(str, "ipv6hint") == 0) {
		return (spr_ipv6hint);
	} else if (strncmp(str, "key", 3) == 0 && strlen(str) > 3) {
		/* parse an arbitrary key */
		unsigned long int key;
		char *endp;

		key = strtoul(str + strlen("key"), &endp, 10);
		assert(endp != NULL);

		if (*endp != '\0' || key >= (unsigned long int)spr_invalid) {
			return (spr_invalid);
		}

		if (key < spr_invalid) {
			return ((uint16_t)key);
		}
	}

	return (spr_invalid);
}
