
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
	uint h, l;
	uint sigs_used;

	//FMT cache
	std::vector<std::map<uint, std::vector<char> > > node_cache;

	int sign (const bvector&, bvector&, hash_func&);

	uint sigs_remaining() {
		return (1 << h) - sigs_used;
	}

	uint hash_size (hash_func&) {
		hf.size();
	}

	uint signature_size (hash_func&) {
		//TODO
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	std::vector<char> check; //tree top verification hash
	uint h;

	uint hash_size() {
		return hf.size();
	}

	uint signature_size() {
		//TODO
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, hash_func&, uint h, uint l);
}

#endif
