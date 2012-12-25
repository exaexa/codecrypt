
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

#include "fmtseq.h"
#include "arcfour.h"

using namespace fmtseq;

void prepare_keygen (arcfour<char>& kg, const std::vector<char>&SK, uint idx)
{
	kg.clear();
	kg.init (8);
	kg.load_key (SK);
	std::vector<char>tmp;
	while (idx) {
		tmp.push_back (idx & 0xff);
		idx >>= 8;
	}
	tmp.resize (16, 0); //prevent chaining to other numbers
	kg.load_key (tmp);
}

//don't feed zero
static uint log2 (uint x)
{
	uint r = 0;
	while (x) {
		++r;
		x >>= 1;
	}
	return r - 1;
}

int fmtseq::generate (pubkey&pub, privkey&priv,
                      prng&rng, hash_func&hf,
                      uint h, uint l)
{

	uint i, j;

	//first off, generate a secret key for commitment generator.
	priv.SK.resize (1 << 8);
	for (i = 0; i < (1 << 8); ++i) {
		priv.SK[i] = rng.random (1 << 8);
	}

	priv.h = h;
	priv.l = l;

	std::vector<privkey::tree_stk_item> stk;
	stk.reserve (h * l + 1);

	uint sigs = 1 << (h * l);

	//number of commitments needed for signature (bits+log2(bits))
	uint commitments = 8 * hf.size();
	commitments += log2 (commitments);

	arcfour<char> generator;
	std::vector<char> x, y, Y;

	x.resize (hf.size() );
	y.resize (hf.size() );

	for (i = 0; i < sigs; ++i) {
		//generate commitments and concat publics into Y
		Y.clear();
		Y.reserve (commitments * hf.size() );
		prepare_keygen (generator, priv.SK, i);
		for (j = 0; j < commitments; ++j) {
			generator.gen (hf.size(), x);
			y = hf (x);
			Y.insert (Y.end(), y.begin(), y.end() );
		}

		stk.push_back (privkey::tree_stk_item (0, hf (Y) ) );

		for (;;) {
			if (stk.size() < 2) break;
			if ( (stk.end() - 1)->level != (stk.end() - 2)->level) break;

			Y.clear();
			Y.insert (Y.end(),
			          (stk.end() - 2)->item.begin(),
			          (stk.end() - 2)->item.end() );
			Y.insert (Y.end(),
			          (stk.end() - 1)->item.begin(),
			          (stk.end() - 1)->item.end() );
			uint l = stk.back().level + 1;
			stk.pop_back();
			stk.pop_back();
			stk.push_back (privkey::tree_stk_item (l, hf (Y) ) );
		}
	}

	//now there's the public verification key available in the stack.
	pub.check = stk.back().item;
	pub.H = h * l;

	return 0;
}

