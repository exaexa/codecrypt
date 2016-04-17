
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

#ifndef _ccr_matrix_h_
#define _ccr_matrix_h_

#include <vector>
#include "types.h"
#include "bvector.h"
#include "vector_item.h"

/*
 * matrix over GF(2) is a vector of columns
 */
class permutation;
class prng;
class matrix : public std::vector<bvector>
{
protected:
	_ccr_declare_vector_item
	_ccr_declare_matrix_item

public:
	uint width() const {
		return size();
	}

	uint height() const {
		if (size()) return item (0).size();
		return 0;
	}

	void resize2 (uint w, uint h, bool def = 0);

	matrix operator* (const matrix&);
	void mult (const matrix&); //right multiply - this*param

	void zero ();
	void unit (uint);

	void compute_transpose (matrix&);
	bool compute_inversion (matrix&,
	                        bool upper_tri = false,
	                        bool lower_tri = false);

	bool set_block (uint, uint, const matrix&);

	bool get_right_square (matrix&);
	bool strip_right_square (matrix&);
	void extend_left_compact (matrix&);

	bool create_goppa_generator (matrix&, permutation&, prng&);
	bool create_goppa_generator (matrix&, const permutation&);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
