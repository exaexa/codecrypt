
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

class privkey
{
public:
	std::vector<char> SK; //secret key
	uint h, l; //l=level count, h=level height (root-leaf path length)
	//therefore, H = h*l
	uint sigs_used;

	//FMT caches
	std::vector<std::vector<char> > exist;
	std::vector<std::vector<char> > desired;

	struct tree_stk_item {
		uint level;
		std::vector<char> item;
		tree_stk_item() {}
		tree_stk_item (uint L, std::vector<char> i)
			: level (L), item (i) {}
	};

	std::vector<std::list<tree_stk_item> > desired_stack;

	int sign (const bvector&, bvector&, hash_func&);

	uint sigs_remaining() {
		return (1 << (h * l) ) - sigs_used;
	}

	uint hash_size (hash_func&hf) {
		return hf.size() * 8;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	std::vector<char> check; //tree top verification hash
	uint H;

	int verify (const bvector&, const bvector&, hash_func&);

	uint hash_size (hash_func&hf) {
		return hf.size() * 8;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, hash_func&, uint h, uint l);
}

#endif
