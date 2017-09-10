
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2017 Mirek Kratochvil <exa.exa@gmail.com>
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

#ifndef _ccr_generator_h_
#define _ccr_generator_h_

#include "chacha.h"
#include "prng.h"

#include <stdint.h>

class ccr_rng : public prng
{
public:
	typedef uint64_t randmax_t;

	chacha20 r;

	ccr_rng() {
		r.init ();
	}

	~ccr_rng() {
		r.clear();
	}

	bool seed (uint bits, bool quick = true);

	uint random (uint n) {
		randmax_t i;
		r.gen (sizeof (randmax_t), (byte*) &i);
		return i % n;
	}
};

#endif
