
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

#ifndef _mce_h_
#define _mce_h_

#include "gf2m.h"
#include "matrix.h"
#include "permutation.h"
#include "polynomial.h"
#include "prng.h"
#include "sencode.h"

/*
 * classical McEliece
 */
namespace mce
{
class privkey
{
public:
	matrix Sinv;
	permutation Pinv;
	polynomial g;
	permutation hperm;
	gf2m fld;

	// derivable things not needed in actual key
	matrix h;
	std::vector<polynomial> sqInv;

	int prepare();
	int decrypt (const bvector&, bvector&);
	int decrypt (const bvector&, bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, uint, prng&);

	uint cipher_size() {
		return Pinv.size();
	}
	uint plain_size() {
		return Sinv.width();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
	uint error_count() {
		return g.degree();
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	matrix G;
	uint t;

	int encrypt (const bvector&, bvector&, prng&);
	int encrypt (const bvector&, bvector&, const bvector&);
	int verify (const bvector&, const bvector&, uint);

	uint cipher_size() {
		return G.width();
	}
	uint plain_size() {
		return G.height();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
	uint error_count() {
		return t;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint m, uint t);
}

#endif

