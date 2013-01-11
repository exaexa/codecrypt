
/*
 * This file is part of Codecrypt.
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

void base64_encode (const std::string& in, std::string&out, int cols)
{
	//note: it could be b64str[64], but we'd need -fpermissive
	static const char b64str[65] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int acc = 0, accbits = 0, idx = 0, idxmax = in.length(), col = 0;
	out.clear();
	out.reserve (idxmax + (4 * idxmax / 10) );
	while (idx < idxmax) {
		if (accbits < 6) {
			acc = (acc << 8) | in[idx++];
			accbits += 8;
		}
		while (accbits >= 6) {
			accbits -= 6;
			out.push_back (b64str[ (acc >> accbits) & 0x3f]);
		}
	}
	if (accbits) {
		out.push_back (b64str[ (acc << (6 - accbits) ) & 0x3f]);
		if (accbits == 2) out.push_back ('=');
		if (accbits <= 4) out.push_back ('=');
	}
}

static void init_dec_str (char s[256])
{
	for (int i = 0; i < 256; ++i) s[i] = -1;

	s['A'] = 0;
	s['B'] = 1;
	s['C'] = 2;
	s['D'] = 3;
	s['E'] = 4;
	s['F'] = 5;
	s['G'] = 6;
	s['H'] = 7;
	s['I'] = 8;
	s['J'] = 9;

	s['K'] = 10;
	s['L'] = 11;
	s['M'] = 12;
	s['N'] = 13;
	s['O'] = 14;
	s['P'] = 15;
	s['Q'] = 16;
	s['R'] = 17;
	s['S'] = 18;
	s['T'] = 19;

	s['U'] = 20;
	s['V'] = 21;
	s['W'] = 22;
	s['X'] = 23;
	s['Y'] = 24;
	s['Z'] = 25;
	s['a'] = 26;
	s['b'] = 27;
	s['c'] = 28;
	s['d'] = 29;

	s['e'] = 30;
	s['f'] = 31;
	s['g'] = 32;
	s['h'] = 33;
	s['i'] = 34;
	s['j'] = 35;
	s['k'] = 36;
	s['l'] = 37;
	s['m'] = 38;
	s['n'] = 39;

	s['o'] = 40;
	s['p'] = 41;
	s['q'] = 42;
	s['r'] = 43;
	s['s'] = 44;
	s['t'] = 45;
	s['u'] = 46;
	s['v'] = 47;
	s['w'] = 48;
	s['x'] = 49;

	s['y'] = 50;
	s['z'] = 51;
	s['0'] = 52;
	s['1'] = 53;
	s['2'] = 54;
	s['3'] = 55;
	s['4'] = 56;
	s['5'] = 57;
	s['6'] = 58;
	s['7'] = 59;

	s['8'] = 60;
	s['9'] = 61;
	s['+'] = 62;
	s['/'] = 63;
}

bool base64_decode (const std::string& in, std::string&out)
{
	static char b64d[256];
	static bool b64d_init = false;

	if (!b64d_init) {
		init_dec_str (b64d);
		b64d_init = true;
	}

	return false;
}

