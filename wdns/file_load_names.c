/*
 * Copyright (c) 2009-2010, 2012 by Farsight Security, Inc.
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

wdns_res
wdns_file_load_names(const char *fname, wdns_callback_name cb, void *user)
{
	FILE *fp;
	char line[1280];
	wdns_res res;
	wdns_name_t name;

	fp = fopen(fname, "r");
	if (fp == NULL)
		return (wdns_res_failure);

	res = wdns_res_success;
	memset(line, 0, sizeof(line));

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (line[0] == '\n' || line[0] == ' ' || line[0] == '#')
			continue;
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';
		res = wdns_str_to_name(line, &name);
		if (res != wdns_res_success)
			break;
		cb(&name, user);
	}

	fclose(fp);
	return (res);
}
