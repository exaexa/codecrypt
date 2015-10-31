
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

#ifndef _ccr_gf2m_h_
#define _ccr_gf2m_h_

#include <vector>
#include "types.h"
#include "sencode.h"

/*
 * galois field of 2^m elements. Stored in an integer, for convenience.
 */

class gf2m
{
public:
	uint poly;
	uint n, m;

	bool create (uint m);

	std::vector<uint> log, antilog;

	inline uint add (uint a, uint b) {
		return a ^ b;
	}

	inline uint mult (uint a, uint b) {
		if (! (a && b)) return 0;
		return antilog[ (log[a] + log[b]) % (n - 1)];
	}

	inline uint exp (uint a, int k) {
		if (!a) return 0;
		return antilog[ (log[a] * k) % (n - 1)];
	}

	inline uint exp (int k) {
		//return x^k
		return exp (1 << 1, k);
	}

	inline uint inv (uint a) {
		if (!a) return 0;
		return antilog[ (n - 1 - log[a]) % (n - 1)];
	}

	inline uint inv_square (uint a) {
		if (!a) return 0;
		return antilog[ (2 * (n - 1 - log[a]))
		                % (n - 1)];
	}

	inline uint div (uint a, uint b) {
		if (! (a && b)) return 0;
		return antilog[ (n - 1 - log[b] + log[a])
		                % (n - 1)];
	}

	inline uint sq_root (uint a) {
		if (!a) return 0;
		uint t = log[a];
		if (t % 2) return antilog[ (t + n - 1) >> 1];
		else return antilog[t >> 1];
	}

	sencode* serialize();
	bool unserialize (sencode*);

	//optimized part of creating alternant check matrix
	template<class iter>
	inline void add_mults (uint base, uint step, iter begin, iter end) {
		if (begin == end || base == 0) return;

		*begin = add (*begin, base);
		++begin;

		if (begin == end || step == 0) return;

		uint lb = log[base], ls = log[step];

		for (; begin != end; ++begin) {
			lb = (lb + ls) % (n - 1);
			*begin = add (*begin, antilog[lb]);
		}
	}
};

#endif
