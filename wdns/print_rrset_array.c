/*
 * Copyright (c) 2009-2010, 2012, 2014 by Farsight Security, Inc.
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

void
wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *rr, unsigned sec)
{
	char *s;

	s = wdns_rrset_array_to_str(rr, sec);
	if (s == NULL)
		return;
	fputs(s, fp);
	my_free(s);
}
