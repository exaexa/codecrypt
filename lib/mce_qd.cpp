
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
				Hsig[i+j] = fld.inv (
				                fld.add (
				                    fld.inv (Hsig[i]),
				                    fld.add (
				                        fld.inv (Hsig[j]),
				                        essence[m-1]
				                    ) ) );
				used.insert (Hsig[i+j]);
				used.insert (fld.inv (
				                 fld.add (
				                     fld.inv (Hsig[i+j]),
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
		permutation bp;
		bp.generate_random (h_block_count, rng);
		bp.permute (bl, blp);

		//discard blocks
		blp.resize (block_count);

		//TODO permute individual blocks

		//TODO co-trace to binary H^
		//TODO systematic H
		//TODO systematic G
		//TODO signature of G

		return 0;
	}
}

int privkey::prepare()
{

	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	return 0;
}

int privkey::decrypt (const bvector&in, bvector&out)
{
	return 0;
}

