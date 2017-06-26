
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

#include "generator.h"
#include "iohelpers.h"

#include <fstream>
#include <vector>

#include <string.h> //for strerror
#include <stdlib.h> //for getenv

static inline uint bytes (uint bits)
{
	return (bits >> 3) + ( (bits & 7) ? 1 : 0);
}

bool ccr_rng::seed (uint bits, bool quick)
{
	std::vector<byte> s;
	std::ifstream f;

	uint b = bytes (bits);
	if (b > 256) b = 256;

	char*user_source = getenv ("CCR_RANDOM_SEED");
	std::string seed_source = user_source ? user_source :
	                          quick ? "/dev/urandom" :
	                          "/dev/random";

	f.open (seed_source, std::ios::in | std::ios::binary);
	if (!f.good()) {
		err ("opening " << seed_source << " failed: "
		     << strerror (errno));
		return false;
	}
	s.resize (b);
	for (uint i = 0; i < b; ++i) f >> s[i];
	f.close();

	r.load_key_vector (s);
	return true;
}

