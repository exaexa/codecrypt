
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

#include "iohelpers.h"

bool redirect_cin (const std::string& fn)
{
	static std::ifstream alt_cin;
	alt_cin.open (fn.c_str(), std::ios::in | std::ios::binary);
	if (alt_cin.fail()) return false;
	std::cin.rdbuf (alt_cin.rdbuf());
	return true;
}

bool redirect_cout (const std::string& fn)
{
	static std::ofstream alt_cout;
	alt_cout.open (fn.c_str(), std::ios::out | std::ios::binary);
	if (alt_cout.fail()) return false;
	std::cout.rdbuf (alt_cout.rdbuf());
	return true;
}

bool redirect_cerr (const std::string& fn)
{
	static std::ofstream alt_cerr;
	alt_cerr.open (fn.c_str(), std::ios::out | std::ios::binary);
	if (alt_cerr.fail()) return false;
	std::cerr.rdbuf (alt_cerr.rdbuf());
	return true;
}

std::string escape_output (const std::string&s)
{
	std::string r;
	const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < s.length(); ++i)
		if (s[i] == '\\') r += "\\\\";
		else if (s[i] >= 0 && s[i] < 0x20) //utf-8 is "negative" here
			switch (s[i]) {
			case '\a':
				r += "\\a";
				break;
			case '\b':
				r += "\\b";
				break;
			case '\x1b':
				r += "\\e";
				break;
			case '\f':
				r += "\\f";
				break;
			case '\n':
				r += "\\n";
				break;
			case '\r':
				r += "\\r";
				break;
			case '\t':
				r += "\\t";
				break;
			case '\v':
				r += "\\v";
				break;
			default:
				r += "\\x";
				r += hex[0xf & (s[i] >> 4)];
				r += hex[0xf & s[i]];
			}
		else r += s[i];
	return r;
}
