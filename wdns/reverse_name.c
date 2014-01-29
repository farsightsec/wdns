wdns_res
wdns_reverse_name(const uint8_t *name, size_t len_name, uint8_t *rev_name) {
	const uint8_t *p;
	size_t len;
	size_t total_len = 0;

	p = name;
	memset(rev_name, 0, len_name);
	rev_name += len_name - 1;

	while ((len = *p) != '\x00') {
		len += 1;
		total_len += len;
		if (total_len > len_name) {
			return (wdns_res_out_of_bounds);
		}
		rev_name -= len;
		memcpy(rev_name, p, len);
		p += len;
	}

	return (wdns_res_success);
}
