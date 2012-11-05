
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

#include "codecrypt.h"

using namespace ccr;

void permutation::compute_inversion (permutation&r) const
{
	r.resize (size(), 0);
	for (uint i = 0; i < size(); ++i)
		r[item (i) ] = i;
}

void permutation::generate_random (uint size, prng&rng)
{
	resize (size, 0);
	uint i;
	for (i = 0; i < size; ++i) item (i) = i;

	//knuth shuffle
	for (i = size - 1; i > 0; --i) {
		uint j = rng.random (i + 1);
		if (i != j) {
			uint t = item (i);
			item (i) = item (j);
			item (j) = t;
		}
	}
}

void permutation::permute_rows (const matrix&a, matrix&r) const
{
	r.resize (a.size() );
	for (uint i = 0; i < a.size(); ++i) permute (a[i], r[i]);
}

