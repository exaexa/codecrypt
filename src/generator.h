
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

#ifndef _generator_h_
#define _generator_h_

#include "arcfour.h"
#include "prng.h"

class arcfour_rng : public prng
{
public:
	arcfour<byte> r;

	arcfour_rng() {
		r.init (8);
	}

	~arcfour_rng() {
		r.clear();
	}

	void seed (uint bits, bool quick);

	uint random (uint n) {
		//rand_max is 2^32.
		return ( (r.gen() << 24) | (r.gen() << 16) | (r.gen() << 8) | r.gen() ) % n;
	}
};

#endif
