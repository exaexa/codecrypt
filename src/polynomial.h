
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

#ifndef _polynomial_h_
#define _polynomial_h_

#include <vector>
#include "types.h"
#include "sencode.h"
#include "vector_item.h"

/*
 * polynomial over GF(2^m) is effectively a vector with a_n binary values
 * with some added operations.
 */
class matrix;
class gf2m;
class prng;
class polynomial : public std::vector<uint>
{
protected:
	_ccr_declare_vector_item
public:
	void strip();
	int degree() const;
	bool zero() const;
	bool one() const;
	void shift (uint);

	uint eval (uint, gf2m&) const;
	uint head() {
		int t;
		if ( (t = degree() ) >= 0) return item (t);
		else return 0;
	}
	void add (const polynomial&, gf2m&);
	void mult (const polynomial&, gf2m&);
	void add_mult (const polynomial&, uint mult, gf2m&);
	void mod (const polynomial&, gf2m&);
	void div (polynomial&, polynomial&, gf2m&);
	void divmod (polynomial&, polynomial&, polynomial&, gf2m&);
	void square (gf2m&);
	void inv (polynomial&, gf2m&);
	void make_monic (gf2m&);

	void sqrt (vector<polynomial>&, gf2m&);
	polynomial gcd (polynomial, gf2m&);
	void ext_euclid (polynomial&, polynomial&, polynomial&, gf2m&, int);

	bool is_irreducible (gf2m&) const;
	void generate_random_irreducible (uint s, gf2m&, prng&);

	bool compute_square_root_matrix (std::vector<polynomial>&, gf2m&);
	void compute_goppa_check_matrix (matrix&, gf2m&);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
