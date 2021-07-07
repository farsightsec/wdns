/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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
