
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

#ifndef _ccr_pwrng_h_
#define _ccr_pwrng_h_

#include "arcfour.h"
#include "prng.h"

#include <stdint.h>

class pw_rng : public prng
{
public:
	/*
	 * Using wide arcfour for this purpose might seem weird, but:
	 *
	 * - it has large memory requirements
	 *   (1Mbit, with possible ~0.95Mbit of entropy)
	 *
	 * - it takes some (very easily parametrizable) amount of time to seed,
	 *   touching the above memory more or less randomly in the process
	 *
	 * - "retry rate" is constrained by how many passwords the human user
	 *   can enter per time unit, which (together with the fact that the
	 *   output of this thing is not supposed to get broadcasted directly)
	 *   mostly disables all the known statistical attacks on arcfour
	 *
	 * - it's a highly nonstandard variant of a well-understood concept
	 *   (therefore a good candidate for codecrypt right?)
	 *
	 * - arcfour is fast, but notably immune to vectorization and similar
	 *   speedups.
	 *
	 * The other variant would be scrypt, which we don't implement for two
	 * reasons:
	 *
	 * - there's currently an scrypt-based cryptocoin, which provides
	 * insane amount of available inversion power against scrypt, which, if
	 * slightly abused, would invert any password-based key in seconds
	 *
	 * - admit it, arcfour is nicer
	 *
	 * Discarding 1M of output is very probably good for most uses (it
	 * permutes well and takes just around 50ms to run on current
	 * mainstream hardware) but YMMV.
	 *
	 * Please report any reasonable cases against this parameter choice.
	 */

	arcfour<uint16_t, 16, 1024 * 1024> r;

	void init () {
		r.init();
	}

	void clear() {
		r.clear();
	}

	bool seed_from_user_password (const std::string& reason,
	                              const std::string& env_var,
	                              bool verify);

	typedef uint64_t randmax_t;
	uint random (uint n) {
		randmax_t i;
		r.gen (sizeof (randmax_t), (byte*) &i);
		return i % n;
	}
};

#endif
