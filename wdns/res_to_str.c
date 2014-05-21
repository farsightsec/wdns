const char *
wdns_res_to_str(wdns_res res)
{
	switch (res) {
	case wdns_res_success:
		return ("success");
	case wdns_res_failure:
		return ("failure");
	case wdns_res_invalid_compression_pointer:
		return ("invalid compression pointer");
	case wdns_res_invalid_length_octet:
		return ("invalid length octet");
	case wdns_res_invalid_opcode:
		return ("invalid opcode");
	case wdns_res_invalid_rcode:
		return ("invalid rcode");
	case wdns_res_len:
		return ("len");
	case wdns_res_malloc:
		return ("malloc");
	case wdns_res_name_len:
		return ("name len");
	case wdns_res_name_overflow:
		return ("name overflow");
	case wdns_res_out_of_bounds:
		return ("out of bounds");
	case wdns_res_overflow:
		return ("overflow");
	case wdns_res_parse_error:
		return ("parse error");
	case wdns_res_qdcount:
		return ("qdcount");
	case wdns_res_unknown_opcode:
		return ("unknown opcode");
	case wdns_res_unknown_rcode:
		return ("unknown rcode");
	}

	return (NULL);
}
