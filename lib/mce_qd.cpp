
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

#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce_qd;

#include "decoding.h"
#include "fwht.h"

#include <set>

static uint sample_from_u (gf2m&fld, prng&rng, std::set<uint>&used)
{
	uint x;
	for (;;) {
		x = rng.random (fld.n);
		if (used.count (x) ) continue;
		used.insert (x);
		return x;
	}
}

static uint choose_random (uint limit, prng&rng, std::set<uint>used)
{
	if (used.size() >= limit - 1) return 0; //die
	for (;;) {
		uint a = 1 + rng.random (limit - 1);
		if (used.count (a) ) continue;
		used.insert (a);
		return a;
	}
}

int mce_qd::generate (pubkey&pub, privkey&priv, prng&rng,
                      uint m, uint T, uint block_discard)
{
	priv.fld.create (m);
	priv.T = T;
	uint t = 1 << T;

	//convenience
	gf2m&fld = priv.fld;
	std::vector<uint>&Hsig = priv.Hsig;
	std::vector<uint>&essence = priv.essence;
	std::vector<uint>&support = priv.support;
	polynomial g;

	//prepare for data
	Hsig.resize (fld.n / 2);
	support.resize (fld.n / 2);
	essence.resize (m);
	//note that q=2^m, algo. n=q/2, log n = m-1

	//retry generating until goppa code is produced.
	for (;;) {

		std::set<uint> used;
		used.clear();

		//first off, compute the H signature

		Hsig[0] = choose_random (fld.n, rng, used);
		essence[m - 1] = fld.inv (Hsig[0]);
		//essence[m-1] is now used as precomputed 1/h_0

		for (uint s = 0; s < m - 1; ++s) {
			uint i = 1 << s; //i = 2^s

			Hsig[i] = choose_random (fld.n, rng, used);
			essence[s] = fld.add (essence[m - 1], fld.inv (Hsig[i]) );
			used.insert (fld.inv (essence[s]) );

			for (uint j = 1; j < i; ++j) {
				Hsig[i + j] = fld.inv
				              (fld.add
				               (fld.inv (Hsig[i]),
				                fld.add (
				                    fld.inv (Hsig[j]),
				                    essence[m - 1]
				                ) ) );
				used.insert (Hsig[i + j]);
				used.insert (fld.inv
				             (fld.add
				              (fld.inv (Hsig[i + j]),
				               essence[m - 1]) ) );
			}
		}

		//assemble goppa polynomial.
		used.clear();

		g.clear();
		g.resize (1, 1); //g(x)=1 so we can multiply it
		polynomial tmp;
		tmp.resize (2, 1); //tmp(x)=x-1
		bool consistent = true;
		for (uint i = 0; i < t; ++i) {
			//tmp(x)=x-z=x-(1/h_i)
			tmp[0] = fld.inv (Hsig[i]);
			if (used.count (tmp[0]) ) {
				consistent = false;
				break;
			}
			used.insert (tmp[0]);

			g.mult (tmp, fld);
		}
		if (!consistent) continue; //retry

		//compute the support, retry if it has two equal elements.
		for (uint i = 0; i < fld.n / 2; ++i) {
			support[i] = fld.add (
			                 fld.inv (Hsig[i]),
			                 essence[m - 1]);

			if (used.count (support[i]) ) {
				consistent = false;
				break;
			}

			//as we are having z's in used, this is not necessary.
			//TODO verify, then TODO maybe delete.
			if (g.eval (support[i], fld) == 0) {
				consistent = false;
				break;
			}

			used.insert (support[i]);
		}
		if (!consistent) continue; //retry

		//now the blocks.
		uint block_size = 1 << T,
		     h_block_count = (fld.n / 2) / block_size;
		uint& block_count = priv.block_count;
		block_count = h_block_count - block_discard;

		//assemble blocks to bl
		std::vector<polynomial> bl, blp;
		bl.resize (h_block_count);
		for (uint i = 0; i < h_block_count; ++i) {
			bl[i].resize (block_size);
			for (uint j = 0; j < block_size; ++j)
				bl[i][j] = Hsig[i * block_size + j];
		}

		//permute them
		priv.block_perm.generate_random (h_block_count, rng);
		priv.block_perm.permute (bl, blp);

		//discard blocks
		blp.resize (block_count);

		//permute individual blocks
		priv.block_perms.resize (block_count);
		bl.resize (blp.size() );
		for (uint i = 0; i < block_count; ++i) {
			priv.block_perms[i] = rng.random (block_size);
			permutation::permute_dyadic (priv.block_perms[i],
			                             blp[i], bl[i]);
		}

		//try several permutations to construct G
		uint attempts = 0;
		for (attempts = 0; attempts < block_count; ++attempts) {

			/*
			 * try computing the redundancy block of G
			 *
			 * First, co-trace H, then compute G in form
			 *
			 * G^T = [I | X]
			 *
			 * Since H*G^T = [L | R] * [I | X] = L + R*X = 0
			 * we have the solution: X = R^1 * L
			 * (thanks to Rafael Misoczki)
			 *
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

			priv.hperm.generate_random (block_count, rng);
			permutation hpermInv;
			priv.hperm.compute_inversion (hpermInv);

			std::vector<std::vector<bvector> > hblocks;
			bvector tmp;
			bool failed;
			uint i, j, k, l;


			//prepare blocks of h
			hblocks.resize (block_count);
			for (i = 0; i < block_count; ++i)
				hblocks[i].resize (fld.m);

			//fill them from Hsig
			for (i = 0; i < block_count; ++i) {
				tmp.from_poly_cotrace (bl[hpermInv[i]], fld);
				for (j = 0; j < fld.m; ++j)
					tmp.get_block (j * block_size,
					               block_size,
					               hblocks[i][j]);
			}

			/* do a modified QD-blockwise gaussian elimination on hblocks */
			failed = false;
			tmp.resize (block_size);
			for (i = 0; i < fld.m; ++i) { //gauss step
				//first, find a nonsingular matrix in the column
				for (j = i; j < fld.m; ++j)
					if (hblocks[block_count - fld.m + i][j]
					    .hamming_weight() % 2) break;
				if (j >= fld.m) { //none found, break;
					failed = true;
					break;
				}

				//bring it to correct position (swap it to i-th row)
				if (j > i) for (k = 0; k < block_count; ++k)
						hblocks[k][i].swap
						(hblocks[k][j]);

				//now normalize the row
				for (j = i; j < fld.m; ++j) {
					l = hblocks [block_count - fld.m + i]
					    [j].hamming_weight();
					if (l == 0) continue; //zero is just okay :]
					if (! (l % 2) ) //singular, make it regular by adding the i-th row
						for (k = 0;
						     k < block_count;
						     ++k)
							hblocks[k][j].add
							(hblocks[k][i]);

					//now a matrix is regular, we can easily make it I.
					//first, multiply the row
					for (k = 0; k < block_count; ++k) {
						//don't overwrite the matrix we're counting with
						if (k == block_count - fld.m + i) continue;
						fwht_dyadic_multiply
						(hblocks[block_count - fld.m + i][j],
						 hblocks[k][j], tmp);
						hblocks[k][j] = tmp;
					}
					//change the block on the diagonal
					fwht_dyadic_multiply
					(hblocks[block_count - fld.m + i][j],
					 hblocks[block_count - fld.m + i][j], tmp);
					hblocks[block_count - fld.m + i][j] = tmp;

					//and zero the column below diagonal
					if (j > i) for (k = 0; k < block_count; ++k)
							hblocks[k][j].add
							(hblocks[k][i]);
				}
			}

			if (failed) continue;

			for (i = 0; i < fld.m; ++i) { //jordan step
				//normalize diagonal
				for (k = 0; k < block_count - i; ++k) {
					//we can safely rewrite the diagonal here (nothing's behind it)
					fwht_dyadic_multiply
					(hblocks[block_count - i - 1][fld.m - i - 1],
					 hblocks[k][fld.m - i - 1], tmp);
					hblocks[k][fld.m - i - 1] = tmp;
				}

				//now make zeroes above
				for (j = i + 1; j < fld.m; ++j) {
					l = hblocks[block_count - i - 1]
					    [fld.m - j - 1].hamming_weight();
					if (l == 0) continue; //already zero
					if (! (l % 2) ) { //nonsingular, fix it by adding diagonal
						for (k = 0; k < block_count; ++k)
							hblocks[k][fld.m - j - 1].add
							(hblocks[k][fld.m - i - 1]);
					}
					for (k = 0; k < block_count - i; ++k) {
						//overwrite is also safe here
						fwht_dyadic_multiply
						(hblocks[block_count - i - 1]
						 [fld.m - j - 1],
						 hblocks[k][fld.m - j - 1], tmp);
						hblocks[k][fld.m - j - 1] = tmp;
					}
					//I+I=0
					for (k = 0; k < block_count; ++k)
						hblocks[k][fld.m - j - 1].add
						(hblocks[k][fld.m - i - 1]);
				}
			}

			pub.qd_sigs.resize (block_count - fld.m);
			for (uint i = 0; i < block_count - fld.m; ++i) {
				pub.qd_sigs[i].resize (block_size * fld.m);
				for (uint j = 0; j < fld.m; ++j)
					pub.qd_sigs[i].set_block
					(hblocks[i][j], block_size * j);
			}

			break;
		}

		if (attempts == block_count) //generating G failed, retry all
			continue;

		//finish the pubkey
		pub.T = T;

		return 0;
	}
}

int privkey::prepare()
{
	uint s, i, j;
	//compute H signature from essence
	Hsig.resize (fld.n / 2);
	Hsig[0] = fld.inv (essence[fld.m - 1]);
	for (s = 0; s < fld.m - 1; ++s) {
		i = 1 << s; //i = 2^s

		Hsig[i] = fld.inv (fld.add (essence[s], essence[fld.m - 1]) );

		for (j = 1; j < i; ++j)
			Hsig[i + j] = fld.inv
			              (fld.add
			               (fld.inv (Hsig[i]),
			                fld.add (
			                    fld.inv (Hsig[j]),
			                    essence[fld.m - 1]
			                ) ) );
	}

	//goppa polynomial with omega=0
	std::set<uint> used;
	used.clear();

	polynomial g, tmp;
	g.clear();
	g.resize (1, 1); //g(x)=1
	tmp.clear();
	tmp.resize (2, 1); //tmp(x)=x+1
	for (i = 0; i < (1 << T); ++i) {
		tmp[0] = fld.inv (Hsig[i]); //tmp(x)=x+1/h_i
		if (used.count (tmp[0]) )
			return 1;
		used.insert (tmp[0]);
		g.mult (tmp, fld);
	}

	//compute the support with omega=0
	support.resize (fld.n / 2);
	for (i = 0; i < fld.n / 2; ++i) {
		support[i] = fld.add
		             (fld.inv (Hsig[i]),
		              essence[fld.m - 1]);
		//support consistency check
		if (used.count (support[i]) )
			return 1;
		used.insert (support[i]);
	}

	//choose omega
	omega = fld.n;
	for (i = 0; i < fld.n; ++i)
		if (!used.count (i) ) {
			omega = i;
			break;
		}
	if (omega == fld.n) return 1;

	//modify support to omega-ized version
	for (i = 0; i < support.size(); ++i)
		support[i] = fld.add (support[i], omega);

	//modify g to omega-ized version
	g.clear();
	tmp.clear();
	g.resize (1, 1); //g(x)=1
	tmp.resize (2, 1); //tmp(x)=x+1
	for (i = 0; i < (1 << T); ++i) {
		tmp[0] = fld.add (fld.inv (Hsig[i]), omega);
		g.mult (tmp, fld);
	}

	// prepare permuted support, from that prepare permuted check matrix
	// (so that it can be applied directly)
	uint block_size = 1 << T;
	uint pos, blk_perm;
	std::vector<uint> sbl1, sbl2, permuted_support;

	sbl1.resize (block_size);
	sbl2.resize (block_size);
	permuted_support.resize (block_size * block_count);

	//permute support
	for (i = 0; i < (fld.n / 2) / block_size; ++i) {
		pos = block_perm[i];
		if (pos >= block_count) continue; //was discarded
		blk_perm = block_perms[pos];
		pos = hperm[pos];

		//permute i-th block of support
		for (j = 0; j < block_size; ++j)
			sbl1[j] = support[j + i * block_size];

		permutation::permute_dyadic (blk_perm, sbl1, sbl2);

		//store support to permuted support
		for (j = 0; j < block_size; ++j)
			permuted_support[j + pos * block_size] = sbl2[j];
	}

	//prepare Hc
	Hc.resize (block_size * block_count);
	for (i = 0; i < block_size * block_count; ++i) {
		Hc[i].resize (block_size * 2);
		Hc[i][0] = fld.inv (g.eval (permuted_support[i], fld) );
		Hc[i][0] = fld.mult (Hc[i][0], Hc[i][0]);
		for (j = 1; j < 2 * block_size; ++j)
			Hc[i][j] = fld.mult (permuted_support[i],
			                     Hc[i][j - 1]);
	}

	//convert the permuted support to actual lookup
	support_pos.clear();
	//fld.n in support lookup means that it isn't there (we don't have -1)
	support_pos.resize (fld.n, fld.n);
	for (i = 0; i < block_size * block_count; ++i)
		support_pos[permuted_support[i]] = i;

	return 0;
}

int pubkey::encrypt (const bvector & in, bvector & out, prng & rng)
{
	uint t = 1 << T;
	bvector p, g, r, cksum;
	uint i, j, k;

	/*
	 * shortened checksum pair of G is computed blockwise accordingly to
	 * the t-sized square dyadic blocks.
	 */

	//some checks
	if (!qd_sigs.size() ) return 1;
	if (qd_sigs[0].size() % t) return 1;

	uint blocks = qd_sigs[0].size() / t;
	cksum.resize (qd_sigs[0].size(), 0);

	p.resize (t);
	g.resize (t);
	r.resize (t);

	for (i = 0; i < qd_sigs.size(); ++i) {
		//plaintext block
		in.get_block (i * t, t, p);

		for (j = 0; j < blocks; ++j) {
			//checksum block
			qd_sigs[i].get_block (j * t, t, g);

			//block result
			fwht_dyadic_multiply (p, g, r);
			cksum.add_offset (r, t * j);
		}
	}

	//generate t errors
	bvector e;
	e.resize (cipher_size(), 0);
	for (uint n = t; n > 0;) {
		uint p = rng.random (e.size() );
		if (!e[p]) {
			e[p] = 1;
			--n;
		}
	}

	//compute ciphertext
	out = in;
	out.insert (out.end(), cksum.begin(), cksum.end() );
	out.add (e);

	return 0;
}

int privkey::decrypt (const bvector & in, bvector & out)
{
	if (in.size() != cipher_size() ) return 2;
	polynomial synd;
	uint i;

	synd.clear();
	for (i = 0; i < cipher_size(); ++i)
		if (in[i]) synd.add (Hc[i], fld);

	//decoding
	polynomial loc;
	//compute_alternant_error_locator (synd, fld, g, loc);
	compute_alternant_error_locator (synd, fld, 1 << T, loc);

	bvector ev;
	if (!evaluate_error_locator_trace (loc, ev, fld) )
		return 1; //couldn't decode
	//TODO evaluator should return error positions, not bvector. fix it everywhere!

	out = in;
	out.resize (plain_size() );
	//flip error positions of out.
	for (i = 0; i < ev.size(); ++i) if (ev[i]) {
			uint epos = support_pos[fld.inv (i)];
			if (epos == fld.n) {
				//found unexpected support, die.
				out.clear();
				return 1;
			}
			if (epos < plain_size() )
				out[epos] = !out[epos];
		}

	return 0;
}

