
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

#ifndef _bvector_h_
#define _bvector_h_

#include <vector>
#include "types.h"
#include "vector_item.h"
#include "sencode.h"

/*
 * vector over GF(2). We rely on STL's vector<bool> == bit_vector
 * specialization for space efficiency.
 *
 * TODO. This is great, but some operations (ESPECIALLY add()) could be done
 * blockwise for O(cpu_word_size) speedup. Investigate/implement that. haha.
 */
class polynomial;
class gf2m;
class bvector : public std::vector<bool>
{
protected:
	_ccr_declare_vector_item
public:
	uint hamming_weight();
	void add (const bvector&);
	void add_range (const bvector&, uint, uint);
	void add_offset (const bvector&, uint);
	void set_block (const bvector&, uint);
	void get_block (uint, uint, bvector&) const;
	bool operator* (const bvector&); //dot product
	bool zero() const;

	void to_poly (polynomial&, gf2m&) const;
	void from_poly (const polynomial&, gf2m&);

	void to_poly_cotrace (polynomial&, gf2m&) const;
	void from_poly_cotrace (const polynomial&, gf2m&);

	void colex_rank (bvector&) const;
	void colex_unrank (bvector&, uint n, uint k) const;

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
