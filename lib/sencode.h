
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

#ifndef _sencode_h_
#define _sencode_h_

#include <string>
#include <vector>

class sencode
{
public:
	virtual std::string encode() = 0;
	virtual void destroy() {}
};

bool sencode_decode (const std::string&, sencode**);
void sencode_destroy (sencode**);

class sencode_list: public sencode
{
public:
	std::vector<sencode*> items;

	virtual std::string encode();
	virtual void destroy();
};

class sencode_int: public sencode
{
public:
	int i;
	sencode_int (int I) {
		i = I;
	}

	virtual std::string encode();
};

class sencode_bytes: public sencode
{
public:
	std::string b;
	sencode_bytes (const std::string&s) {
		b = s;
	}

	virtual std::string encode();
};

#endif
