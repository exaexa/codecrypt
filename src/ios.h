
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

#ifndef _ios_h_
#define _ios_h_

//operator overloads very useful for debugging/hacking
#include <iostream>
#include "polynomial.h"
#include "permutation.h"
#include "gf2m.h"
#include "matrix.h"
#include "bvector.h"

std::ostream& operator<< (std::ostream&o, const polynomial&);
std::ostream& operator<< (std::ostream&o, const permutation&);
std::ostream& operator<< (std::ostream&o, const gf2m&);
std::ostream& operator<< (std::ostream&o, const matrix&);
std::ostream& operator<< (std::ostream&o, const bvector&);

#endif
