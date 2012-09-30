
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce_qd;

#include "decoding.h"

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
                      uint m, uint T, uint block_count)
{
	priv.fld.create (m);
	priv.T = T;
	uint t = 1 << T;

	//convenience
	gf2m&fld = priv.fld;
	std::vector<uint>&Hsig = priv.Hsig;
	std::vector<uint>&essence = priv.essence;
	std::vector<uint>&support = priv.support;
	polynomial&g = priv.g;

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
		essence[m-1] = fld.inv (Hsig[0]);
		//essence[m-1] is now used as precomputed 1/h_0

		for (uint s = 0; s < m - 1; ++s) {
			uint i = 1 << s; //i = 2^s

			Hsig[i] = choose_random (fld.n, rng, used);
			essence[s] = fld.add (essence[m-1], fld.inv (Hsig[i]) );
			used.insert (fld.inv (essence[s]) );

			for (uint j = 1; j < i; ++j) {
				Hsig[i+j] = fld.inv
				            (fld.add
				             (fld.inv (Hsig[i]),
				              fld.add (
				                  fld.inv (Hsig[j]),
				                  essence[m-1]
				              ) ) );
				used.insert (Hsig[i+j]);
				used.insert (fld.inv
				             (fld.add
				              (fld.inv (Hsig[i+j]),
				               essence[m-1]) ) );
			}
		}

		//from now on, we fix 'omega' from the paper to zero.

		//compute the support, retry if it has two equal elements.
		used.clear();
		bool consistent = true;
		used.insert (0); //zero is forbidden
		for (uint i = 0; i < fld.n / 2; ++i) {
			support[i] = fld.add (
			                 fld.inv (Hsig[i]),
			                 essence[m-1]);

			if (used.count (support[i]) ) {
				consistent = false;
				break;
			}
			used.insert (support[i]);
		}
		if (!consistent) continue; //retry

		//assemble goppa polynomial.
		g.clear();
		g.resize (1, 1); //g(x)=1 so we can multiply it
		polynomial tmp;
		tmp.resize (2, 1); //tmp(x)=x-1
		for (uint i = 0; i < t; ++i) {
			//tmp(x)=x-z=x-(1/h_i)
			tmp[0] = fld.inv (Hsig[i]);
			g.mult (tmp, fld);
		}

		//now the blocks.
		uint block_size = 1 << T,
		     h_block_count = (fld.n / 2) / block_size;

		//assemble blocks to bl
		std::vector<std::vector<uint> > bl, blp;
		bl.resize (block_size);
		for (uint i = 0; i < h_block_count; ++i)
			bl[i] = std::vector<uint>
			        (Hsig.begin() + i * block_size,
			         Hsig.begin() + (i + 1) * block_size);

		//permute them
		priv.block_perm.generate_random (h_block_count, rng);
		priv.block_perm.permute (bl, blp);

		//discard blocks
		blp.resize (block_count);

		//permute individual blocks
		priv.block_count = block_count;
		priv.block_perms.resize (block_count);
		bl.resize (blp.size() );
		for (uint i = 0; i < block_count; ++i) {
			priv.block_perms[i] = rng.random (block_size);
			permutation::permute_dyadic (priv.block_perms[i],
			                             blp[i], bl[i]);
		}

		//co-trace blocks to binary H^, retry creating G using hperm.
		matrix Hc;
		polynomial col;
		Hc.resize (block_count * block_size);

		matrix r, ri, l;

		for (;;) {
			priv.hperm.generate_random (block_count, rng);

			for (uint i = 0; i < block_count; ++i)
				for (uint j = 0; j < block_size; ++j) {
					permutation::permute_dyadic
					(j, bl[priv.hperm[i]], col);
					Hc[i*block_size + j].from_poly_cotrace
					(col, fld);
				}

			/*
			 * try computing the redundancy block of G
			 *
			 * Since H*G^T = [L | R] * [I | X] = L + R*X = 0
			 * we have the solution: X = R^1 * L
			 */

			Hc.get_right_square (r);
			if (!r.compute_inversion (ri) )
				continue; //retry with other hperm
			Hc.strip_right_square (l);
			ri.mult (l);
		}

		/*
		 * Redundancy-checking part of G is now (transposed) in ri.
		 * Get QD signatures by getting every t'th row (transposed).
		 */

		pub.T = T;
		pub.k = (block_count - fld.m) * block_size;
		pub.qd_sigs.resize (ri.width() / t);
		for (uint i = 0; i < ri.width(); i += t)
			pub.qd_sigs[i/t] = ri[i];

		return 0;
	}
}

int privkey::prepare()
{
	//compute H signature from essence
	Hsig.resize (fld.n / 2);
	Hsig[0] = fld.inv (essence[fld.m-1]);
	for (uint s = 0; s < fld.m - 1; ++s) {
		uint i = 1 << s; //i = 2^s

		//TODO verify this
		Hsig[i] = fld.inv (fld.add (essence[s], essence[fld.m-1]) );

		for (uint j = 1; j < i; ++j)
			Hsig[i+j] = fld.inv
			            (fld.add
			             (fld.inv (Hsig[i]),
			              fld.add (
			                  fld.inv (Hsig[j]),
			                  essence[fld.m-1]
			              ) ) );
	}

	//compute the support
	support.resize (fld.n / 2);
	for (uint i = 0; i < fld.n / 2; ++i) {
		support[i] = fld.add
		             (fld.inv (Hsig[i]),
		              essence[fld.m-1]);

	}

	//goppa polynomial
	g.clear();
	g.resize (1, 1);
	polynomial tmp;
	tmp.resize (2, 1);
	uint t = 1 << T;
	for (uint i = 0; i < t; ++i) {
		tmp[0] = fld.inv (Hsig[i]);
		g.mult (tmp, fld);
	}

	//sqInv
	g.compute_square_root_matrix (sqInv, fld);

	return 0;
}

#include "fwht.h"

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	uint t = 1 << T;
	bvector p, g, r, cksum;

	/*
	 * shortened checksum pair of G is computed blockwise accordingly to
	 * the t-sized square dyadic blocks.
	 */

	//some checks
	if (in.size() != k) return 1;
	if (!qd_sigs.size() ) return 1;
	if (qd_sigs[0].size() % t) return 1;

	uint blocks = qd_sigs[0].size() / t;
	cksum.resize (qd_sigs[0].size(), 0);

	p.resize (t);
	g.resize (t);
	r.resize (t);

	for (uint i = 0; i < blocks; ++i) {
		//plaintext block
		for (uint k = 0; k < t; ++k) p[k] = in[k+i*t];

		for (uint j = 0; j < qd_sigs.size(); ++j) {
			//checksum block
			for (uint k = 0; k < t; ++k) g[k] = qd_sigs[i][k+j*t];

			//block result
			fwht_dyadic_multiply (p, g, r);
			cksum.add_offset (r, t * j);
		}
	}

	//generate t errors
	bvector e;
	e.resize (k + qd_sigs[0].size(), 0);
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

int privkey::decrypt (const bvector&in, bvector&out)
{
	//TODO decoding
	return 0;
}

