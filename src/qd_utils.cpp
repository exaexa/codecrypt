
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

#include "qd_utils.h"

#include <vector>

/*
 * we count on that all integers are sufficiently large.
 * They should be, largest value occuring should be O(k*n) if initial vector is
 * consisted only from {0,1}^n, and we don't usually have codes of this size.
 */

static void fwht (std::vector<int> x, std::vector<int>&r)
{
	uint bs, s;
	s = x.size();
	bs = s >> 1;
	r.swap (x);
	while (bs) {
		x.swap (r);
		for (uint i = 0; i < s; ++i) {
			if ( (i / bs) & 1)
				r[i] = x[i - bs] - x[i];
			else
				r[i] = x[i] + x[i + bs];
		}
		bs >>= 1;
	}
}

/*
 * we expect correct parameter size and preallocated out. Last 3 parameters are
 * used as a cache - just supply the same vectors everytime when you're doing
 * this multiple times.
 */
void fwht_dyadic_multiply (const bvector& a, const bvector& b, bvector& out,
                           std::vector<int>&t,
                           std::vector<int>&A,
                           std::vector<int>&B)
{

	uint i;

	//lift everyting to Z.
	for (i = 0; i < a.size(); ++i) t[i] = a[i];
	fwht (t, A);

	for (i = 0; i < b.size(); ++i) t[i] = b[i];
	fwht (t, B);

	//multiply diagonals to A
	for (i = 0; i < A.size(); ++i) A[i] *= B[i];
	fwht (A, t);

	uint bitpos = a.size(); //no problem as a.size() == 1<<m == 2^m
	for (i = 0; i < t.size(); ++i) out[i] = (t[i] & bitpos) ? 1 : 0;
}

bool qd_to_right_echelon_form (std::vector<std::vector<bvector> >&mat)
{
	uint w = mat.size();
	if (!w) return false;
	uint h = mat[0].size();
	if (!h) return false;
	uint bs = mat[0][0].size();

	uint i, j, k, l;

	/*
	 * Inversion is done the quasi-dyadic way:
	 *
	 * - because for QD matrix m=delta(h) the product
	 *   m*m = sum(h) * I, binary QD matrix m is either
	 *   inversion of itself (m*m=I) or isn't invertible
	 *   and m*m=0. sum(h), the "count of ones in QD
	 *   signature mod 2", easily determines the result.
	 *
	 * - Using blockwise invertions/multiplications,
	 *   gaussian elimination needed to invert the right
	 *   square of H can be performed in O(m^2*block_count)
	 *   matrix operations. Matrix operations are either
	 *   addition (O(t) on QDs), multiplication(O(t log t)
	 *   on QDs) or inversion (O(t), as shown above).
	 *   Whole proces is therefore quite fast.
	 *
	 * Gaussian elimination on the QD signature should
	 * result in something like this: (for m=3, t=4)
	 *
	 *   1010 0101 1001 1000 0000 0000
	 *   0101 1100 1110 0000 1000 0000
	 *   0111 1110 0100 0000 0000 1000
	 */

	bvector tmp;
	tmp.resize (bs);

	std::vector<int> c1, c2, c3;
	c1.resize (bs);
	c2.resize (bs);
	c3.resize (bs);

	for (i = 0; i < h; ++i) { //gauss step
		//first, find a nonsingular matrix in the column
		for (j = i; j < h; ++j)
			if (mat[w - h + i][j]
			    .hamming_weight() % 2) break;
		if (j >= h) //none found, die!
			return false;

		//bring it to correct position (swap it to i-th row)
		if (j > i) for (k = 0; k < w; ++k)
				mat[k][i].swap
				(mat[k][j]);

		//now normalize the row
		for (j = i; j < h; ++j) {
			l = mat [w - h + i]
			    [j].hamming_weight();
			if (l == 0) continue; //zero is just okay :]
			if (! (l % 2) ) //singular, make it regular by adding the i-th row
				for (k = 0;
				     k < w;
				     ++k)
					mat[k][j].add
					(mat[k][i]);

			//now a matrix is regular, we can easily make it I.
			//first, multiply the row
			for (k = 0; k < w; ++k) {
				//don't overwrite the matrix we're counting with
				if (k == w - h + i) continue;
				fwht_dyadic_multiply
				(mat[w - h + i][j],
				 mat[k][j], tmp, c1, c2, c3);
				mat[k][j] = tmp;
			}
			//change the block on the diagonal
			fwht_dyadic_multiply
			(mat[w - h + i][j],
			 mat[w - h + i][j], tmp, c1, c2, c3);
			mat[w - h + i][j] = tmp;

			//and zero the column below diagonal
			if (j > i) for (k = 0; k < w; ++k)
					mat[k][j].add
					(mat[k][i]);
		}
	}

	for (i = 0; i < h; ++i) { //jordan step
		//normalize diagonal
		for (k = 0; k < w - i; ++k) {
			//we can safely rewrite the diagonal here (nothing's behind it)
			fwht_dyadic_multiply
			(mat[w - i - 1][h - i - 1],
			 mat[k][h - i - 1], tmp, c1, c2, c3);
			mat[k][h - i - 1] = tmp;
		}

		//now make zeroes above
		for (j = i + 1; j < h; ++j) {
			l = mat[w - i - 1]
			    [h - j - 1].hamming_weight();
			if (l == 0) continue; //already zero
			if (! (l % 2) ) { //nonsingular, fix it by adding diagonal
				for (k = 0; k < w; ++k)
					mat[k][h - j - 1].add
					(mat[k][h - i - 1]);
			}
			for (k = 0; k < w - i; ++k) {
				//overwrite is also safe here
				fwht_dyadic_multiply
				(mat[w - i - 1]
				 [h - j - 1],
				 mat[k][h - j - 1], tmp, c1, c2, c3);
				mat[k][h - j - 1] = tmp;
			}
			//I+I=0
			for (k = 0; k < w; ++k)
				mat[k][h - j - 1].add
				(mat[k][h - i - 1]);
		}
	}

	return true;
}

uint choose_random (uint limit, prng&rng, std::set<uint>&used)
{
	if (used.size() >= limit - 1) return 0; //die
	for (;;) {
		uint a = 1 + rng.random (limit - 1);
		if (used.count (a) ) continue;
		used.insert (a);
		return a;
	}
}

