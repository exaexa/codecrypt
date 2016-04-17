
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

#ifndef _ccr_mce_qcmdpc_h_
#define _ccr_mce_qcmdpc_h_

#include <vector>
#include <stdint.h>

#include "bvector.h"
#include "matrix.h"
#include "prng.h"
#include "sencode.h"
#include "types.h"

/*
 * quasi-cyclic MDPC McEliece
 * Implemented accordingly to the paper by Misoczki, Tillich, Sendrier and Barreto.
 */
namespace mce_qcmdpc
{
class privkey
{
public:
	matrix H; //elems = _cols_ of H blocks (at least 2)
	uint t;
	uint rounds;
	uint delta;

	int decrypt (const bvector&, bvector&);
	int decrypt (const bvector&, bvector&, bvector&);
	int prepare();

	uint cipher_size() {
		return H[0].size() * H.size();
	}
	uint plain_size() {
		return H[0].size() * (H.size() - 1);
	}
	uint error_count() {
		return t;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	matrix G; //elems = top lines of right-side G blocks
	uint t; //error count

	int encrypt (const bvector&, bvector&, prng&);
	int encrypt (const bvector&, bvector&, const bvector&);

	uint cipher_size() {
		return G[0].size() * (G.size() + 1);
	}
	uint plain_size() {
		return G[0].size() * G.size();
	}
	uint error_count() {
		return t;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint blocksize, uint blocks, uint wi,
              uint t, uint rounds, uint delta);
}

#endif
