
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

#ifndef _ccr_mce_qd_h_
#define _ccr_mce_qd_h_

#include <vector>

#include "bvector.h"
#include "gf2m.h"
#include "matrix.h"
#include "permutation.h"
#include "polynomial.h"
#include "prng.h"
#include "sencode.h"
#include "types.h"

/*
 * compact Quasi-dyadic McEliece
 * according to Misoczki, Barreto, Compact McEliece Keys from Goppa Codes.
 *
 * Good security, extremely good speed with extremely reduced key size.
 * Recommended for encryption, but NEEDS some plaintext conversion -- either
 * Fujisaki-Okamoto or Kobara-Imai are known to work good. Without the
 * conversion, the encryption itself is extremely weak.
 */
namespace mce_qd
{
class privkey
{
public:
	std::vector<uint> essence;
	gf2m fld;   //we fix q=2^fld.m=fld.n, n=q/2
	uint T;     //the QD's t parameter is 2^T.
	permutation block_perm; //order of blocks
	std::vector<uint> block_perms; //dyadic permutations of blocks
	permutation hperm; //block permutation of H block used to get G

	//derivable stuff
	//pre-permuted positions of support rows and support content
	std::vector<uint> support_pos, permuted_support;
	//generating polynomial
	polynomial g;

	int decrypt (const bvector&, bvector&);
	int decrypt (const bvector&, bvector&, bvector&);
	int prepare();

	uint cipher_size() {
		return (1 << T) * hperm.size();
	}
	uint plain_size() {
		return (1 << T) * (hperm.size() - fld.m);
	}
	uint error_count() {
		return 1 << T;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	uint T;
	matrix qd_sigs;

	int encrypt (const bvector&, bvector&, prng&);
	int encrypt (const bvector&, bvector&, const bvector&);

	uint cipher_size() {
		return plain_size() + qd_sigs[0].size();
	}
	uint plain_size() {
		return (1 << T) * qd_sigs.size();
	}
	uint error_count() {
		return 1 << T;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint m, uint T, uint b, uint bd);
}

#endif
