
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
using namespace ccr::cfs_qd;

#include "decoding.h"
#include "qd_utils.h"

#include <set>

int cfs_qd::generate (pubkey&pub, privkey&priv, prng&rng,
                      uint m, uint T, uint t, uint block_discard)
{
	priv.fld.create (m);
	priv.T = T;
	uint block_size = 1 << T;
	if (t > block_size) return 2;
	priv.t = t;

	//convenience
	gf2m&fld = priv.fld;
	std::vector<uint>&essence = priv.essence;

	std::vector<uint> support, Hsig;
	polynomial g;
	uint i, j;

	//prepare for data
	Hsig.resize (fld.n);
	support.resize (fld.n);
	essence.resize (m + 1);
	//note that q=2^m, algo. n=q/2, log n = m-1

	//retry generating until goppa code is produced.
	for (;;) {

		std::cout << "attempt" << std::endl;

		std::set<uint> used;
		used.clear();

		//first off, compute the H signature

		Hsig[0] = choose_random (fld.n, rng, used);
		essence[m] = fld.inv (Hsig[0]);
		//essence[m] is now used as precomputed 1/h_0

		for (uint s = 0; s < m; ++s) {
			i = 1 << s; //i = 2^s

			Hsig[i] = choose_random (fld.n, rng, used);
			essence[s] = fld.add (essence[m], fld.inv (Hsig[i]) );
			used.insert (fld.inv (essence[s]) );

			for (j = 1; j < i; ++j) {
				uint hij = fld.inv
				           (fld.add
				            (fld.inv (Hsig[i]),
				             fld.add (
				                 fld.inv (Hsig[j]),
				                 essence[m]
				             ) ) );
				if ( (!Hsig[i]) || (!Hsig[j]) ) hij = 0;
				Hsig[i + j] = hij;
				if (hij) {
					used.insert (Hsig[i + j]);
					/*used.insert (fld.inv
					             (fld.add
					              (fld.inv (Hsig[i + j]),
					               essence[m]) ) );*/
				}
			}
		}

		std::cout << "Gen Hsig: ";
		for (i = 0; i < fld.n; ++i) std::cout << Hsig[i] << ' ';
		std::cout << std::endl;

		//let's play with blocks.
		uint block_size = 1 << T,
		     h_block_count = fld.n / block_size,
		     block_count = h_block_count - block_discard;

		//check if we have enough good blocks.
		std::vector<bool> block_status;
		uint badblocks;
		block_status.resize (h_block_count);

		badblocks = 0;
		for (i = 0; i < h_block_count; ++i) {
			block_status[i] = true;
			for (j = 0; j < block_size; ++j)
				if (!Hsig[i * block_size + j]) {
					block_status[i] = false;
					break;
				}
			if (!block_status[i]) ++badblocks;
		}

		std::cout << "badblocks: " << badblocks << std::endl;

		if (badblocks > block_discard) continue; //don't have enough good blocks
		if (!block_status[0]) continue; //cannot assemble goppa poly

		std::cout << "lol contd." << std::endl;

		//reconstruct g
		used.clear();
		g.clear();
		g.resize (1, 1); //g(x)=1 so we can multiply it
		polynomial tmp;
		tmp.resize (2, 1); //tmp(x)=x-1
		bool consistent = true;
		for (i = 0; i < t; ++i) {
			//tmp(x)=x-z=x-(1/h_i) where h_i is squared!
			tmp[0] = fld.inv (Hsig[i]);
			if (used.count (tmp[0]) ) {
				consistent = false;
				break;
			}
			used.insert (tmp[0]);
			g.mult (tmp, fld);
		}
		if (!consistent) continue; //retry

		std::cout << "lol have g: " << g;

		//compute the support, retry if it has two equal elements.
		for (i = 0; i < fld.n; ++i) {
			if (!block_status[i / block_size]) continue;
			support[i] = fld.add (
			                 fld.inv (Hsig[i]),
			                 essence[m]);

			std::cout << "support " << i << " = " << support[i] << std::endl;
			if (used.count (support[i]) ) {
				std::cout << "support inconsistent at " << i << std::endl;
				++badblocks;
				block_status[i / block_size] = false;
				break;
			}

			used.insert (support[i]);
		}

		std::cout << "bad: " << badblocks << std::endl;
		if (badblocks > block_discard) continue;

		//assemble blocks to bl
		std::vector<polynomial> bl, blp;
		bl.resize (h_block_count);
		for (i = 0; i < h_block_count; ++i) {
			bl[i].resize (block_size);
			for (j = 0; j < block_size; ++j)
				bl[i][j] = Hsig[i * block_size + j];
		}

		//permute the blocks. first move the damaged to discard area
		priv.block_perm.generate_identity (h_block_count);
		uint oks = h_block_count;
		for (i = 0; i < oks; ++i)
			if (!block_status[i]) {
				std::cout << "removing one" << std::endl;
				--oks;
				priv.block_perm[i] = oks;
				priv.block_perm[oks] = i;
				//swap block statuses as well
				bool tmp = block_status[i];
				block_status[i] = block_status[oks];
				block_status[oks] = tmp;
				--i;
			}
		std::cout << "BLOCK " << priv.block_perm;
		permutation rest_perm;
		rest_perm.generate_random (oks, rng);
		//permute the undamaged part of block_perm by hand TODO FIXME
		//for (i = 0; i < oks; ++i) rest_perm[i] = priv.block_perm[rest_perm[i]];
		//for (i = 0; i < oks; ++i) priv.block_perm[i] = rest_perm[i];

		//now we can safely permute and discard blocks
		priv.block_perm.permute (bl, blp);
		blp.resize (block_count);

		//permute individual blocks
		priv.block_perms.resize (block_count);
		bl.resize (blp.size() );
		for (i = 0; i < block_count; ++i) {
			priv.block_perms[i] = rng.random (block_size);
			permutation::permute_dyadic (priv.block_perms[i],
			                             blp[i], bl[i]);
		}

		//construct H
		pub.qd_sigs.resize (fld.m);
		bvector col;
		bvector block;
		for (i = 0; i < fld.m; ++i)
			pub.qd_sigs[i].resize (block_count * block_size);
		for (i = 0; i < block_count; ++i) {
			col.from_poly_cotrace (bl[i], fld);
			for (j = 0; j < fld.m; ++j) {
				col.get_block (j * block_size,
				               block_size, block);

				pub.qd_sigs[j].set_block
				(block, block_size * i);
			}
		}

		//finish the pubkey
		pub.T = T;
		pub.t = t;

		return 0;
	}
}

int privkey::prepare()
{
	uint s, i, j, k;
	std::vector<uint> Hsig, support;
	uint omega;

	uint block_count = block_perms.size(),
	     block_size = 1 << T;

	//compute H signature from essence
	Hsig.resize (fld.n);
	Hsig[0] = fld.inv (essence[fld.m]);
	for (s = 0; s < fld.m; ++s) {
		i = 1 << s; //i = 2^s

		Hsig[i] = fld.inv (fld.add (essence[s], essence[fld.m]) );

		for (j = 1; j < i; ++j)
			Hsig[i + j] = fld.inv
			              (fld.add
			               (fld.inv (Hsig[i]),
			                fld.add (
			                    fld.inv (Hsig[j]),
			                    essence[fld.m]
			                ) ) );
	}
	std::cout << "Gen Hsig: ";
	for (i = 0; i < fld.n; ++i) std::cout << Hsig[i] << ' ';
	std::cout << std::endl;


	//goppa polynomial with omega=0
	std::set<uint> used;
	used.clear();

	polynomial tmp;
	g.clear();
	g.resize (1, 1); //g(x)=1
	tmp.clear();
	tmp.resize (2, 1); //tmp(x)=x+1
	for (i = 0; i < t; ++i) {
		tmp[0] = fld.inv (Hsig[i]); //tmp(x)=x+1/h_i
		if (used.count (tmp[0]) )
			return 1;
		std::cout << tmp[0] << std::endl;
		used.insert (tmp[0]);
		g.mult (tmp, fld);
	}

	std::cout << "HERE 1" << std::endl;
	//compute the support with omega=0
	support.resize (fld.n);
	for (i = 0; i < fld.n; ++i) {
		//don't compute with discarded support
		if (block_perm[i / block_size] >= block_count) continue;
		support[i] = fld.add
		             (fld.inv (Hsig[i]),
		              essence[fld.m]);
		std::cout << "support " << i << " = " << support[i] << std::endl;
		if (used.count (support[i]) ) //invalid support
			return 1;
		used.insert (support[i]);
	}

	std::cout << "HERE LOLOLOLOLOL" << std::endl;
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
	for (i = 0; i < t; ++i) {
		tmp[0] = fld.add (fld.inv (Hsig[i]), omega);
		g.mult (tmp, fld);
	}

	g.compute_square_root_matrix (sqInv, fld);

	// prepare permuted support, from that prepare permuted check matrix
	// (so that it can be applied directly)
	uint pos;
	std::vector<uint> sbl1, sbl2, permuted_support;

	sbl1.resize (block_size);
	sbl2.resize (block_size);
	permuted_support.resize (block_size * block_count);

	//permute support
	for (i = 0; i < fld.n / block_size; ++i) {
		pos = block_perm[i];
		if (pos >= block_count) continue; //was discarded

		//permute i-th block of support
		for (j = 0; j < block_size; ++j)
			sbl1[j] = support[j + i * block_size];

		permutation::permute_dyadic (block_perms[pos], sbl1, sbl2);

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

	/*
	 * TODO move this to separate function
	 *
	 * prepare the matrix to compute decodable syndrome from QD matrix. From Barreto's slides:
	 *
	 * A is public check matrix
	 * H is private check matrix producing decodable syndromes
	 *
	 * H=SA for some S
	 * therefore if
	 *
	 * synd = A * codeword
	 *
	 * then
	 *
	 * S*synd = H*codeword
	 *
	 * and S = H * A^T * (A * A^T)^-1
	 */

	std::vector<std::vector<uint> > ma, mb, tmpa, tmph;
	std::vector<uint> t1, t2;

	/*
	 * First, precompute the matrices A and H
	 */

	tmpa.resize (t);
	tmph.resize (t);
	for (i = 0; i < t; ++i) {
		tmpa[i].resize (fld.n);
		tmph[i].resize (fld.n);
	}

	for (i = 0; i < t; ++i)
		permutation::permute_dyadic (i, Hsig, tmpa[i]);

	std::cout << "TMPA" << std::endl;
	for (i = 0; i < t; ++i) {
		for (j = 0; j < fld.n; ++j) std::cout << tmpa[i][j] << ' ';
		std::cout << std::endl;
	}


	polynomial tmpcol;
	for (i = 0; i < fld.n; ++i) {
		tmpcol.resize (2);
		tmpcol[0] = support[i];
		tmpcol[1] = 1;
		tmpcol.inv (g, fld);
		tmpcol.resize (t, 0);
		for (j = 0; j < t; ++j) tmph[j][i] = tmpcol[j];
	}

	/*
	 * compute H * H^T to ma and A * H^T to mb.
	 */

	ma.resize (t);
	mb.resize (t);
	for (i = 0; i < t; ++i) {
		ma[i].resize (t, 0);
		mb[i].resize (t, 0);
	}

	for (i = 0; i < t; ++i) for (j = 0; j < t; ++j) {
			for (k = 0; k < fld.n; ++k) {
				ma[i][j] = fld.add (ma[i][j], fld.mult (tmph[i][k], tmph[j][k]) );
				mb[i][j] = fld.add (mb[i][j], fld.mult (tmpa[i][k], tmph[j][k]) );
			}
		}

	std::cout << "MA" << std::endl;
	for (i = 0; i < t; ++i) {
		for (j = 0; j < t; ++j) std::cout << ma[i][j] << ' ';
		std::cout << std::endl;
	}

	std::cout << "MB" << std::endl;
	for (i = 0; i < t; ++i) {
		for (j = 0; j < t; ++j) std::cout << mb[i][j] << ' ';
		std::cout << std::endl;
	}

	/*
	 * now invert mb into ma as (mb|ma) to (I|ma*mb^-1)
	 *
	 * (result will be transposed, but that's actually good for our purpose)
	 */

	uint x;
	//gauss step
	for (i = 0; i < t; ++i) {
		//find pivot
		for (j = i; j < t; ++j) if (mb[j][i] != 0) break;
		if (j >= t) return 1; //no pivot -> not invertible
		if (j > i) {
			ma[j].swap (ma[i]);
			mb[j].swap (mb[i]);
		}
		//normalize
		x = fld.inv (mb[i][i]);
		for (j = 0; j < t; ++j) {
			ma[i][j] = fld.mult (ma[i][j], x);
			mb[i][j] = fld.mult (mb[i][j], x);
		}
		//zero rows below
		for (j = i + 1; j < t; ++j) {
			x = mb[j][i];
			if (x == 0) continue;
			for (k = 0; k < t; ++k) {
				ma[j][k] = fld.add (ma[j][k], fld.mult (x, ma[i][k]) );
				mb[j][k] = fld.add (mb[j][k], fld.mult (x, mb[i][k]) );
			}
		}
	}

	//jordan step
	std::cout << "jordan step..." << std::endl;
	for (i = 0; i < t; ++i) {
		for (j = i + 1; j < t; ++j) {
			x = mb[t - j - 1][t - i - 1];
			if (x == 0) continue;
			for (k = 0; k < t; ++k) {
				ma[t - j - 1][k] = fld.add (ma[t - j - 1][k], fld.mult (x, ma[t - i - 1][k]) );
				mb[t - j - 1][k] = fld.add (mb[t - j - 1][k], fld.mult (x, mb[t - i - 1][k]) );
			}
		}
	}

	//result is now transposed in ma.
	syndS.resize (t);
	for (i = 0; i < t; ++i) {
		syndS[i].resize (t);
		for (j = 0; j < t; ++j) syndS[i][j] = ma[i][j];
	}

	std::cout << "SyndS is OKAY!" << std::endl;

	polynomial decsynd, loc;
	for (i = 0; i < t; ++i)
		decsynd.add_mult (syndS[i], Hsig[i], fld);
	compute_goppa_error_locator (decsynd, fld, g, sqInv, loc);
	std::cout << "TEST LOCATOR: " << loc;

	return 0;
}

int privkey::sign (const bvector& hash, bvector&signature,
                   uint delta, uint attempts, prng&rng)
{
	if (hash.size() != hash_size() ) return 2;

	polynomial synd, decsynd, tmp, loc;
	bvector ev, h2;

	uint i;

	for (uint att = 0; att < attempts; ++att) {
		h2 = hash;
		for (i = 0; i < delta; ++i) {
			uint p = rng.random (h2.size() );
			h2[p] = !h2[p];
		}

		h2.to_poly_cotrace (synd, fld);

		std::cout << "SYND" << synd;

		decsynd.clear();
		for (i = 0; i < t; ++i)
			decsynd.add_mult (syndS[i], synd[i], fld);

		std::cout << "SYND PREP" << decsynd;

		compute_goppa_error_locator (decsynd, fld, g, sqInv, loc);
		if (!evaluate_error_locator_trace (loc, ev, fld) ) continue;
		//we might have it!
		std::cout << ev;
		signature.clear();
		signature.resize (signature_size(), 0);

		for (i = 0; i < fld.n; ++i) if (ev[i]) {
				uint epos = support_pos[i];
				if (epos == fld.n) break; //bad luck, undecodable
				signature[epos] = 1;
			}
		if (i == fld.n) return 0;
	}
	return 1; //no attempts left.
}

int pubkey::verify (const bvector&signature, const bvector&hash, uint delta)
{
	if (signature.size() != signature_size() ) return 2;
	if (hash.size() != hash_size() ) return 2;

	uint i, j;
	uint block_size = 1 << T;
	bvector synd, b1, b2;

	synd.resize (t * qd_sigs.size(), 0);
	//compute the syndrome
	for (i = 0; i < signature_size(); ++i) {
		if (!signature[i]) continue;

		//this is actually quite fast, as it happens only several times
		for (j = 0; j < qd_sigs.size(); ++j) {
			qd_sigs[j].get_block ( (i / block_size) *block_size,
			                       block_size, b1);
			permutation::permute_dyadic (i % block_size, b1, b2);
			b2.resize (t);
			synd.add_offset (b2, t * j);
		}
	}

	std::cout << "SYNDROME: " << synd;
	synd.add (hash);
	std::cout << "DIFF: " << synd;
	if (synd.hamming_weight() > delta) return 1;

	return 0;
}
