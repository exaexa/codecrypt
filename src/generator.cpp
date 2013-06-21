
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

#include "generator.h"

#include <fstream>
#include <vector>

static inline uint bytes (uint bits)
{
	return (bits >> 3) + ( (bits & 7) ? 1 : 0);
}

void arcfour_rng::seed (uint bits, bool quick)
{
	std::vector<byte> s;
	std::ifstream f;

	uint b = bytes (bits);
	if (b > 256) b = 256;

	f.open (quick ? "/dev/urandom" : "/dev/random",
	        std::ios::in | std::ios::binary);
	s.resize (b);
	for (uint i = 0; i < b; ++i) f >> s[i];
	f.close();

	r.load_key (s);
	r.discard (4096);
}

