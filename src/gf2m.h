
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

#ifndef _ccr_gf2m_h_
#define _ccr_gf2m_h_

#include <vector>
#include "types.h"
#include "sencode.h"

/*
 * galois field of 2^m elements. Stored in an integer, for convenience.
 */

class gf2m
{
public:
	uint poly;
	uint n, m;

	bool create (uint m);

	std::vector<uint> log, antilog;

	uint add (uint, uint);
	uint mult (uint, uint);
	uint exp (uint, int);
	uint exp (int);
	uint inv (uint);
	uint sq_root (uint);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
