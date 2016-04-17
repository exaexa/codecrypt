
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

#ifndef _ccr_symkey_h_
#define _ccr_symkey_h_

#include <iostream>
#include <string>
#include <list>
#include <set>
#include <vector>

#include "types.h"
#include "generator.h"
#include "sencode.h"

class symkey
{
public:
	std::set<std::string> ciphers, hashes;

	uint blocksize;

	std::vector<byte> key;

	sencode* serialize();
	bool unserialize (sencode*);

	bool encrypt (std::istream&, std::ostream&, prng&);
	int decrypt (std::istream&, std::ostream&);

	bool is_valid();
	bool create (const std::string&, prng&);
};

#endif
