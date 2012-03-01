wdns_res
_wdns_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
		   uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount)
{
	if (len < WDNS_LEN_HEADER)
		return (wdns_res_len);

	load_net16(p, id);
	load_net16(p + 2, flags);
	load_net16(p + 4, qdcount);
	load_net16(p + 6, ancount);
	load_net16(p + 8, nscount);
	load_net16(p + 10, arcount);

	return (wdns_res_success);
}
