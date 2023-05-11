/*
 * Copyright (c) 2009-2010, 2012, 2014-2015, 2019 by Farsight Security, Inc.
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

static bool
is_digit(char c)
{
	if (c >= '0' && c <= '9')
		return (true);
	return (false);
}

static wdns_res
_wdns_str_to_name(const char *str, wdns_name_t *name, bool downcase)
{
	const char *p;
	size_t label_len;
	ssize_t slen;
	uint8_t c, *oclen, *data;
	wdns_res res;

	res = wdns_res_parse_error;

	p = str;
	slen = strlen(str);

	if (slen == 1 && *p == '.') {
		name->len = 1;
		name->data = my_malloc(1);
		name->data[0] = '\0';
		return (wdns_res_success);
	}

	name->len = 0;
	name->data = my_malloc(WDNS_MAXLEN_NAME + 1);

	data = name->data;
	label_len = 0;
	oclen = data++;
	name->len++;

	for (;;) {
		c = *p++;
		label_len++;

		if (slen == 0) {
			/* end of input */
			if (name->len == WDNS_MAXLEN_NAME) {
				res = wdns_res_name_overflow;
				goto out;
			}
			*oclen = --label_len;
			*data++ = '\0';
			name->len++;
			break;
		}

		if (name->len >= WDNS_MAXLEN_NAME) {
			res = wdns_res_name_overflow;
			goto out;
		}

		if (c >= 'A' && c <= 'Z') {
			/* an upper case letter; downcase it */
			if (downcase)
				c |= 0x20;
			*data++ = c;
			name->len++;
		} else if (c == '\\' && !is_digit(*p)) {
			/* an escaped character */
			if (slen <= 0)
				goto out;
			*data++ = *p;
			name->len++;
			p++;
			slen--;
		} else if (c == '\\' && slen >= 3) {
			/* an escaped octet */
			char d[4];
			char *endptr = NULL;
			long int val;

			d[0] = *p++;
			d[1] = *p++;
			d[2] = *p++;
			d[3] = '\0';
			slen -= 3;
			if (!is_digit(d[0]) || !is_digit(d[1]) || !is_digit(d[2]))
				goto out;
			val = strtol(d, &endptr, 10);
			if (endptr != NULL && *endptr == '\0'
			    && val >= 0 && val <= 255)
			{
				uint8_t uval;

				uval = (uint8_t) val;
				*data++ = uval;
				name->len++;
			} else {
				goto out;
			}
		} else if (c == '\\') {
			/* should not occur */
			goto out;
		} else if (c == '.') {
			/* end of label */
			*oclen = --label_len;
			if (label_len == 0)
				goto out;
			oclen = data++;
			if (slen > 1)
				name->len++;
			label_len = 0;
		} else if (c != '\0') {
			*data++ = c;
			name->len++;
		}

		slen--;
	}

	return (wdns_res_success);

out:
	my_free(name->data);
	return (res);
}

wdns_res
wdns_str_to_name(const char *str, wdns_name_t *name)
{
	return _wdns_str_to_name(str, name, true);
}

wdns_res
wdns_str_to_name_case(const char *str, wdns_name_t *name)
{
	return _wdns_str_to_name(str, name, false);
}
