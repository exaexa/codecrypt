
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

#ifndef _ccr_hashfile_h_
#define _ccr_hashfile_h_

#include "types.h"
#include "sencode.h"

#include <iostream>
#include <string>
#include <vector>
#include <map>

class hashfile
{
public:
	typedef std::map<std::string, std::vector<byte> > hashes_t;
	hashes_t hashes;

	bool create (std::istream&);
	int verify (std::istream&);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
