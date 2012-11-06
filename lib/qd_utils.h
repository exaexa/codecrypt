
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

#ifndef _qdutils_h_
#define _qdutils_h_

#include "codecrypt.h"

using namespace ccr;

//FWHT matrix mult in O(n log n). parameters MUST be of 2^m size.
void fwht_dyadic_multiply (const bvector&, const bvector&, bvector&);

//create a generator using fwht
bool qd_to_right_echelon_form (std::vector<std::vector<bvector> >&matrix);

#endif

