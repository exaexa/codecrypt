
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

#ifndef _ccr_qdutils_h_
#define _ccr_qdutils_h_

#include <vector>
#include <set>

#include "bvector.h"
#include "prng.h"

/*
 * FWHT matrix mult in O(n log n). parameters MUST be of 2^m size.
 *
 * c1-c3 are caches. Just supply the same vector objects everytime, it's gonna
 * be a lot faster.
 */
void fwht_dyadic_multiply (const bvector&, const bvector&, bvector&,
                           std::vector<int>& c1,
                           std::vector<int>& c2,
                           std::vector<int>& c3);

//create a generator using fwht
bool qd_to_right_echelon_form (std::vector<std::vector<bvector> >&matrix);

//disjunct random set selector. Doesn't select 0 (thus 0 is returned on failure)
uint choose_random (uint limit, prng&rng, std::set<uint>&used);

#endif

