
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

#ifndef _fmtseq_h_
#define _fmtseq_h_

#include <vector>
#include <list>
#include "types.h"
#include "bvector.h"
#include "sencode.h"
#include "hash.h"
#include "prng.h"

/*
 * FMTseq - Merkle signatures with fractal tree traversal, using original
 * Lamport signatures for speed.
 */
namespace fmtseq
{

//helper function used to calculate hash sizes percisely
inline uint fmtseq_commitments (uint l)
{
	uint x = l;
	while (x) {
		++l;
		x >>= 1;
	}
	return l;
}

class privkey
{
public:
	std::vector<byte> SK; //secret key
	uint h, l; //l=level count, h=level height (root-leaf path length)
	//therefore, H = h*l
	uint sigs_used;
	uint hs;

	//FMT caches
	std::vector<std::vector<std::vector<byte> > > exist, desired;

	struct tree_stk_item {
		uint level, pos;
		std::vector<byte> item;
		tree_stk_item() {}
		tree_stk_item (uint L, uint P, std::vector<byte> i)
			: level (L), pos (P), item (i) {}

		sencode* serialize();
		bool unserialize (sencode*);
	};
	std::vector<std::vector<tree_stk_item> > desired_stack;
	std::vector<uint> desired_progress;

	int sign (const bvector&, bvector&, hash_func&);

	uint sigs_remaining() {
		return (1 << (h * l) ) - sigs_used;
	}

	uint hash_size () {
		return hs;
	}

	uint signature_size (hash_func&hf) {
		return ( (h * l + fmtseq_commitments (hs) ) * hf.size() * 8) + (h * l);
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	std::vector<byte> check; //tree top verification hash
	uint H, hs;

	int verify (const bvector&, const bvector&, hash_func&);

	uint hash_size () {
		return hs;
	}

	uint signature_size (hash_func&hf) {
		return ( (H + fmtseq_commitments (hs) ) * hf.size() * 8) + H;
	}


	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, hash_func&, uint hs, uint h, uint l);
}

#endif
