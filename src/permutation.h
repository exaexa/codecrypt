
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

#ifndef _ccr_permutation_h_
#define _ccr_permutation_h_

#include <vector>
#include "types.h"
#include "vector_item.h"
#include "sencode.h"

/*
 * permutation is stored as transposition table ordered from zero
 * e.g. (13)(2) is [2,1,0]
 */
class prng;
class matrix;
class permutation : public std::vector<uint>
{
protected:
	_ccr_declare_vector_item
public:
	void compute_inversion (permutation&) const;

	void generate_random (uint n, prng&);
	void generate_identity (uint n) {
		resize (n);
		for (uint i = 0; i < n; ++i)
			item (i) = i;
	}

	template<class A, class R> void permute (const A&a, R&r) const {
		r.resize (a.size() );
		for (uint i = 0; i < size(); ++i) r[item (i) ] = a[i];
	}

	template<class A, class R> void permute_inv (const A&a, R&r) const {
		r.resize (a.size() );
		for (uint i = 0; i < size(); ++i) r[i] = a[item (i)];
	}

	void permute_rows (const matrix&, matrix&) const;

	//work-alike for dyadic permutations.
	template<class A, class R> static bool permute_dyadic
	(uint sig, const A&a, R&r) {

		//check if the thing has size 2^n
		uint s = a.size();
		while (s > 1) {
			if (s & 1) return false;
			s >>= 1;
		}

		if (sig >= a.size() ) return false;

		r.resize (a.size() );

		uint i, t, x;
		for (i = 0; i < a.size(); ++i) {
			r[sig] = a[i];

			//flip the correct bit in signature
			t = i + 1;
			x = 1;
			while (! (t & 1) ) {
				t >>= 1;
				x <<= 1;
			}
			sig ^= x;
		}

		return true;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
