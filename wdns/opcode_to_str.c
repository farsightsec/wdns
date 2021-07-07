/*
 * Copyright (c) 2009, 2012 by Farsight Security, Inc.
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
wdns_opcode_to_str(uint16_t opcode)
{
	switch (opcode) {
	case WDNS_OP_QUERY:	return ("QUERY");
	case WDNS_OP_IQUERY:	return ("IQUERY");
	case WDNS_OP_STATUS:	return ("STATUS");
	case WDNS_OP_NOTIFY:	return ("NOTIFY");
	case WDNS_OP_UPDATE:	return ("UPDATE");
	}

	return (NULL);
}
