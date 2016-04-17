
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

#ifndef _ccr_sencode_h_
#define _ccr_sencode_h_

#include <string>
#include <vector>

#include "types.h"

/*
 * data serialization format
 */

class sencode
{
public:
	virtual std::string encode() = 0;
	virtual void destroy() {}

	virtual ~sencode() {}
};

sencode* sencode_decode (const std::string&);
void sencode_destroy (sencode*);

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
	uint i;
	sencode_int (uint I) {
		i = I;
	}

	virtual std::string encode();
};

class sencode_bytes: public sencode
{
public:
	std::string b;
	sencode_bytes (const std::string&s) : b (s) {}
	sencode_bytes (const std::vector<byte>&a) : b (a.begin(), a.end()) {}

	virtual std::string encode();
};

#endif

