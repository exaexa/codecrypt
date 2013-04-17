
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

#ifndef _ccr_nd_h_
#define _ccr_nd_h_

#include "gf2m.h"
#include "matrix.h"
#include "permutation.h"
#include "polynomial.h"
#include "prng.h"
#include "sencode.h"

/*
 * classical Niederreiter
 */
namespace nd
{
class privkey
{
public:
	matrix Sinv;
	permutation Pinv;
	polynomial g;
	gf2m fld;

	//derivable.
	std::vector<polynomial> sqInv;

	int decrypt (const bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, uint, prng&);
	int prepare();

	uint cipher_size() {
		return Sinv.size();
	}
	uint plain_size() {
		return Pinv.size();
	}
	uint plain_weight() {
		return g.degree();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
	uint signature_weight() {
		return plain_weight();
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	matrix H;
	uint t;

	int encrypt (const bvector&, bvector&);
	int verify (const bvector&, const bvector&, uint);

	uint cipher_size() {
		return H.height();
	}
	uint plain_size() {
		return H.width();
	}
	uint plain_weight() {
		return t;
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
	uint signature_weight() {
		return plain_weight();
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint m, uint t);
}

#endif
