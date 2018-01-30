
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2016 Mirek Kratochvil <exa.exa@gmail.com>
 *
 * Codecrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Codecrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Codecrypt. If not, see <http://www.gnu.org/licenses/>.
 */

#include "base64.h"

static const unsigned char b64str[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64d[256];
static bool b64d_init = false;

void base64_encode (const std::string& in, std::string&out, int cols)
{
	//note: it could be b64str[64], but we'd need -fpermissive
	unsigned int acc = 0;
	int accbits = 0, idx = 0, idxmax = in.length(), col = 0;
	out.clear();
	out.reserve (idxmax + (2 * idxmax / 5));  //reserve around 140%
	while (idx < idxmax) {
		if (accbits < 6) {
			acc = (acc << 8) | (unsigned char) in[idx++];
			accbits += 8;
		}
		while (accbits >= 6) {
			accbits -= 6;
			out.push_back (b64str[ (acc >> accbits) & 0x3f]);

			if (cols && ( (++col) >= cols)) {
				out.push_back ('\n');
				col = 0;
			}
		}
	}
	if (accbits) {
		out.push_back (b64str[ (acc << (6 - accbits)) & 0x3f]);
		if (accbits == 2) out.push_back ('=');
		if (accbits <= 4) out.push_back ('=');
	}
}

static void init_b64d ()
{
	if (b64d_init) return;
	for (int i = 0; i < 256; ++i) b64d[i] = -1;
	for (int i = 0; i < 64; ++i) b64d[b64str[i]] = i;
	b64d_init = true;
}

static inline bool is_white (unsigned char c)
{
	return (c == '\n') || (c == '\r') || (c == ' ') || (c == '\t');
}

static inline bool is_b64 (unsigned char c)
{
	return (c >= 'a' && c <= 'z')
	       || (c >= 'A' && c <= 'Z')
	       || (c >= '0' && c <= '9')
	       || c == '+' || c == '/'
	       || c == '=';
}

static void eat_white (const std::string&in, int&idx, int idxmax)
{
	for (; (idx < idxmax) && is_white (in[idx]); ++idx);
}

static bool eat_4 (const std::string&in, int&idx, int idxmax, int a[4])
{
	for (int i = 0; i < 4; ++i) {
		eat_white (in, idx, idxmax);
		if ( (idx < idxmax) && is_b64 (in[idx]))
			a[i] = in[idx];
		else return false;
		++idx;
	}
	return true;
}

bool base64_decode (const std::string& in, std::string&out)
{
	init_b64d();

	int idx = 0, idxmax = in.length();

	out.clear();
	out.reserve (3 * in.length() / 4);

	//start parsing
	int c[4];
	while (eat_4 (in, idx, idxmax, c)) {
		for (int i = 0; i < 4; ++i) {
			if (c[i] < 0 || c[i] >= 256) return false;
			c[i] = b64d[c[i]]; // '=' gets converted to -1
		}

		//consistency checks
		if ( (c[0] == -1) || (c[1] == -1)) return false;
		if ( (c[2] == -1) && (c[3] != -1)) return false;

		int tmp = (c[0] << 18) | (c[1] << 12);
		if (c[2] != -1) tmp |= c[2] << 6;
		if (c[3] != -1) tmp |= c[3];

		out.push_back ( (tmp >> 16) & 0xff);

		if (c[2] != -1) // middle byte is valid
			out.push_back ( (tmp >> 8) & 0xff);

		if (c[3] != -1) // last byte is valid
			out.push_back (tmp & 0xff);
		else
			break; //there were ='s, terminate.
	}

	//there shouldn't be anything more than whitespace now
	eat_white (in, idx, idxmax);
	return idx == idxmax;
}

