
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

#ifndef _ccr_rc4_h_
#define _ccr_rc4_h_

#include "sc.h"

#include <vector>

template<class inttype = byte, int bits = 8, int disc_bytes = 0>
class arcfour : public streamcipher
{
	std::vector<inttype> S;
	inttype I, J;
	inttype mask;
public:
	void init () {
		size_t Ssize = 1 << bits;
		I = J = 0;
		S.resize (Ssize);
		mask = ~ (inttype) 0;
		if ( (inttype) (1 << bits)) mask %= 1 << bits;
		for (size_t i = 0; i < Ssize; ++i) S[i] = i;
	}

	void clear() {
		init();
	}

	void load_key (const inttype*begin, const inttype*end) {
		inttype j, t;
		size_t i;
		const inttype *keypos;

		//eat whole key iteratively, even if longer than permutation
		for (; begin < end; begin += mask + 1) {
			j = 0;
			for (i = 0, keypos = begin;
			     i <= mask;
			     ++i, ++keypos) {
				if (keypos >= end) keypos = begin; //rotate
				j = (j + S[i] + (*keypos)) & mask;
				t = S[j];
				S[j] = S[i];
				S[i] = t;
			}
		}

		discard (disc_bytes);
	}

	inttype gen() {
		I = (I + 1) & mask;
		J = (J + S[I]) & mask;

		register inttype t;
		t = S[J];
		S[J] = S[I];
		S[I] = t;

		return S[ (S[I] + S[J]) & mask];
	}

	void gen (size_t n, inttype*out) {
		if (out)
			for (size_t i = 0; i < n; ++i) out[i] = gen();
		else
			for (size_t i = 0; i < n; ++i) gen();
	}

	void gen (size_t n, std::vector<inttype>&out) {
		out.resize (n);
		gen (n, & (out[0]));
	}

	size_t key_size() {
		return 256;
	}

	size_t block_size() {
		return 1;
	}
};

#endif

