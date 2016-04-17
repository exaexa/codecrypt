
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

#include "mce_qd.h"

using namespace mce_qd;

#include "decoding.h"
#include "qd_utils.h"
#include "iohelpers.h"

#include <set>

static void print_attack_warning()
{
	static bool printed = false;
	if (printed) return;
	err ("\n***MCEQD SECURITY WARNING***\n\n"
	     "Security of the QD-McEliece variant was greatly reduced to less than 2^30\n"
	     "by an algebraic attack! The functions are kept only for compatibility\n"
	     "and will be removed soon. Use `-g help' for other encryption variants.");
	printed = true;
}

int mce_qd::generate (pubkey&pub, privkey&priv, prng&rng,
                      uint m, uint T, uint block_count, uint block_discard)
{
	print_attack_warning();

	//convenience
	gf2m&fld = priv.fld;
	std::vector<uint>&essence = priv.essence;

	//initial stuff and sizes
	fld.create (m);
	priv.T = T;
	uint t = 1 << T,
	     block_size = t,
	     h_block_count = block_count + block_discard,
	     n = h_block_count * t;

	if (block_count <= m) return 2; //lower bound on block_count
	if (n > fld.n / 2) return 2; //n <= q/2

	std::vector<uint> support, Hsig;
	polynomial g;
	uint i, j;

	//prepare data arrays
	Hsig.resize (n);
	support.resize (n);
	essence.resize (m);

	//retry generating until goppa code is produced.
	for (;;) {

		std::set<uint> used;
		used.clear();

		//first off, compute the H signature

		Hsig[0] = choose_random (fld.n, rng, used);
		essence[m - 1] = fld.inv (Hsig[0]);
		//essence[m-1] is now used as precomputed 1/h_0

		for (uint s = 0; ( (uint) 1 << s) < n; ++s) {
			i = 1 << s; //i = 2^s

			Hsig[i] = choose_random (fld.n, rng, used);
			essence[s] = fld.add (essence[m - 1], fld.inv (Hsig[i]));
			used.insert (fld.inv (essence[s]));

			for (j = 1; j < i; ++j) {
				if (i + j >= n) break;
				Hsig[i + j] = fld.inv
				              (fld.add
				               (fld.inv (Hsig[i]),
				                fld.add (
				                    fld.inv (Hsig[j]),
				                    essence[m - 1]
				                )));
				used.insert (Hsig[i + j]);
				used.insert (fld.inv
				             (fld.add
				              (fld.inv (Hsig[i + j]),
				               essence[m - 1])));
			}
		}

		//assemble goppa polynomial.
		used.clear();

		g.clear();
		g.resize (1, 1); //g(x)=1 so we can multiply it
		polynomial tmp;
		tmp.resize (2, 1); //tmp(x)=x-1
		bool consistent = true;
		for (i = 0; i < t; ++i) {
			//tmp(x)=x-z=x-(1/h_i)
			tmp[0] = fld.inv (Hsig[i]);
			if (used.count (tmp[0])) {
				consistent = false;
				break;
			}
			used.insert (tmp[0]);

			g.mult (tmp, fld);
		}
		if (!consistent) continue; //retry

		//compute the support, retry if it has two equal elements.
		for (i = 0; i < n; ++i) {
			support[i] = fld.add (
			                 fld.inv (Hsig[i]),
			                 essence[m - 1]);

			if (used.count (support[i])) {
				consistent = false;
				break;
			}

			used.insert (support[i]);
		}
		if (!consistent) continue; //retry

		//now the blocks. First assemble blocks to bl
		std::vector<polynomial> bl, blp;
		bl.resize (h_block_count);
		for (i = 0; i < h_block_count; ++i) {
			bl[i].resize (block_size);
			for (j = 0; j < block_size; ++j)
				bl[i][j] = Hsig[i * block_size + j];
		}

		//permute them
		priv.block_perm.generate_random (h_block_count, rng);
		priv.block_perm.permute (bl, blp);

		//discard blocks
		blp.resize (block_count);

		//permute individual blocks
		priv.block_perms.resize (block_count);
		bl.resize (blp.size());
		for (i = 0; i < block_count; ++i) {
			priv.block_perms[i] = rng.random (block_size);
			permutation::permute_dyadic (priv.block_perms[i],
			                             blp[i], bl[i]);
		}

		//try several permutations to construct G
		uint attempts = 0;
		for (attempts = 0; attempts < block_count; ++attempts) {

			priv.hperm.generate_random (block_count, rng);
			permutation hpermInv;
			priv.hperm.compute_inversion (hpermInv);

			std::vector<std::vector<bvector> > hblocks;
			bvector col;

			//prepare blocks of h
			hblocks.resize (block_count);
			for (i = 0; i < block_count; ++i)
				hblocks[i].resize (fld.m);

			//fill them from Hsig
			for (i = 0; i < block_count; ++i) {
				col.from_poly_cotrace (bl[hpermInv[i]], fld);
				for (j = 0; j < fld.m; ++j)
					col.get_block (j * block_size,
					               block_size,
					               hblocks[i][j]);
			}

			/* do a modified QD-blockwise gaussian elimination on hblocks.
			 * If it fails, retry. */
			if (!qd_to_right_echelon_form (hblocks)) continue;

			pub.qd_sigs.resize2 (block_count - fld.m,
			                     block_size * fld.m, 0);
			for (i = 0; i < block_count - fld.m; ++i) {
				for (j = 0; j < fld.m; ++j)
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
	print_attack_warning();

	uint s, i, j;
	std::vector<uint> Hsig, support;
	uint omega;

	uint block_size = 1 << T,
	     block_count = hperm.size(),
	     h_block_count = block_perm.size(),
	     n = h_block_count * block_size;

	//compute H signature from essence
	Hsig.resize (n);
	Hsig[0] = fld.inv (essence[fld.m - 1]);
	for (s = 0; ( (uint) 1 << s) < n; ++s) {
		i = 1 << s; //i = 2^s

		Hsig[i] = fld.inv (fld.add (essence[s], essence[fld.m - 1]));

		for (j = 1; j < i; ++j) {
			if (i + j >= n) break;
			Hsig[i + j] = fld.inv
			              (fld.add
			               (fld.inv (Hsig[i]),
			                fld.add (
			                    fld.inv (Hsig[j]),
			                    essence[fld.m - 1]
			                )));
		}
	}

	//goppa polynomial with omega=0
	std::set<uint> used;
	used.clear();

	polynomial tmp;
	g.clear();
	g.resize (1, 1); //g(x)=1
	tmp.clear();
	tmp.resize (2, 1); //tmp(x)=x+1
	for (i = 0; i < block_size; ++i) {
		tmp[0] = fld.inv (Hsig[i]); //tmp(x)=x+1/h_i
		if (used.count (tmp[0]))
			return 1;
		used.insert (tmp[0]);
		g.mult (tmp, fld);
	}

	//compute the support with omega=0
	support.resize (n);
	for (i = 0; i < n; ++i) {
		//don't check discarded support
		if (block_perm[i / block_size] >= block_count) continue;
		support[i] = fld.add
		             (fld.inv (Hsig[i]),
		              essence[fld.m - 1]);
		//support consistency check
		if (used.count (support[i]))
			return 1;
		used.insert (support[i]);
	}

	//choose some omega
	omega = fld.n;
	for (i = 0; i < fld.n; ++i)
		if (!used.count (i)) {
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
	for (i = 0; i < block_size; ++i) {
		tmp[0] = fld.add (fld.inv (Hsig[i]), omega);
		g.mult (tmp, fld);
	}

	// prepare permuted support, from that prepare permuted check matrix
	// (so that it can be applied directly)
	uint pos, blk_perm;
	std::vector<uint> sbl1, sbl2;

	sbl1.resize (block_size);
	sbl2.resize (block_size);
	permuted_support.resize (block_size * block_count);

	//permute support
	for (i = 0; i < h_block_count; ++i) {
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

	//convert the permuted support to actual lookup
	support_pos.clear();
	//fld.n in support lookup means that it isn't there (we don't have -1)
	support_pos.resize (fld.n, fld.n);
	for (i = 0; i < block_size * block_count; ++i)
		support_pos[permuted_support[i]] = i;

	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	uint s = cipher_size(),
	     t = 1 << T;
	if (t > s) return 1;

	//create error vector
	bvector e;
	e.resize (s, 0);
	for (uint n = t; n > 0;) {
		uint p = rng.random (s);
		if (!e[p]) {
			e[p] = 1;
			--n;
		}
	}
	return encrypt (in, out, e);
}

int pubkey::encrypt (const bvector & in, bvector & out, const bvector&errors)
{
	print_attack_warning();

	uint t = 1 << T;
	bvector p, g, r, cksum;
	uint i, j;

	/*
	 * shortened checksum pair of G is computed blockwise accordingly to
	 * the t-sized square dyadic blocks.
	 */

	//some checks
	if (!qd_sigs.width()) return 1;
	if (qd_sigs.height() % t) return 1;
	if (in.size() != plain_size()) return 2;
	if (errors.size() != cipher_size()) return 2;

	uint blocks = qd_sigs.height() / t;
	cksum.resize (qd_sigs.height(), 0);

	p.resize (t);
	g.resize (t);
	r.resize (t);

	std::vector<int> c1, c2, c3;
	c1.resize (t);
	c2.resize (t);
	c3.resize (t);

	for (i = 0; i < qd_sigs.size(); ++i) {
		//plaintext block
		in.get_block (i * t, t, p);

		for (j = 0; j < blocks; ++j) {
			//checksum block
			qd_sigs[i].get_block (j * t, t, g);

			//block result
			fwht_dyadic_multiply (p, g, r, c1, c2, c3);
			cksum.add_offset (r, t * j);
		}
	}

	//compute ciphertext
	out = in;
	out.append (cksum);
	out.add (errors);

	return 0;
}

int privkey::decrypt (const bvector & in, bvector & out)
{
	bvector tmp_errors;
	return decrypt (in, out, tmp_errors);
}

int privkey::decrypt (const bvector & in, bvector & out, bvector & errors)
{
	print_attack_warning();

	if (in.size() != cipher_size()) return 2;
	polynomial synd;
	uint i, tmp;

	/*
	 * compute the syndrome from alternant check matrix
	 * that is H_alt = Vdm(L) * Diag(g(L_i)^{-2})
	 */
	uint h_size = 1 << (T + 1); //= 2*block_size
	synd.clear();
	synd.resize (h_size, 0);
	for (i = 0; i < cipher_size(); ++i) if (in[i]) {
			tmp = fld.inv_square //g(Li)^{-2}
			      (g.eval (permuted_support[i], fld));
			fld.add_mults (tmp, permuted_support[i],
			               synd.begin(), synd.end());
		}

	//decoding
	polynomial loc;
	compute_alternant_error_locator (synd, fld, 1 << T, loc);

	bool failed = false;
	bvector ev;
	if (!evaluate_error_locator_trace (loc, ev, fld))
		failed = true;

	out = in;
	out.resize (plain_size());
	errors.clear();
	errors.resize (cipher_size(), 0);
	//flip error positions of out.
	for (i = 0; i < ev.size(); ++i) if (ev[i]) {
			uint epos = support_pos[fld.inv (i)];
			if (epos == fld.n || epos >= cipher_size()) {
				//found unexpected/wrong support, die.
				failed = true;
				continue;
			}
			errors[epos] = 1;
			if (epos < plain_size())
				out[epos] = !out[epos];
		}

	return failed ? 1 : 0;
}

