
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

#include <vector>

#include <sys/types.h>

template<class inttype> class arcfour
{
	std::vector<inttype> S;
	inttype I, J;
	size_t mod;
public:
	bool init (size_t bits) {
		if (bits > 8 * sizeof (inttype) ) return false;
		I = J = 0;
		S.resize (1 << bits);
		mod = 1 << bits;
		for (size_t i = 0; i < (1 << bits); ++i) {
			S[i] = i;
		}
		return true;
	}

	void clear() {
		I = J = 0;
		mod = 0;
		S.clear();
	}

	void load_key (const std::vector<inttype>&K) {
		inttype j = 0, t;
		for (size_t i = 0; i < mod; ++i) {
			j = (j + S[i] + K[i % K.size()]) % mod;
			t = S[j];
			S[j] = S[i];
			S[i] = t;
		}
	}

	inttype gen() {
		I = (I + 1) % mod;
		J = (J + S[I]) % mod;

		register inttype t;
		t = S[J];
		S[J] = S[I];
		S[I] = t;

		return S[ (S[I] + S[J]) % mod];
	}

	void discard (size_t n) {
		for (size_t i = 0; i < n; ++i) gen();
	}

	void gen (size_t n, std::vector<inttype>&out) {
		out.resize (n);
		for (size_t i = 0; i < n; ++i) out[i] = gen();
	}
};

#endif

