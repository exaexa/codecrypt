
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce_oc;

#include "decoding.h"

int mce_oc::generate (pubkey&pub, privkey&priv,
                      prng&rng, uint m, uint t, uint n)
{
	priv.fld.create (m);

	uint	subplain_size = priv.fld.n - (m * t),
	        codeword_size = (n * subplain_size) + (m * t);

	//prepare resulting generator matrix
	matrix g;
	g.resize (codeword_size);
	for (uint i = 0; i < codeword_size; ++i)
		g[i].resize (subplain_size * n);

	//generate n subcodes
	priv.codes.resize (n);
	for (uint i = 0; i < n; ++i) {
		privkey::subcode& sc = priv.codes[i];

		sc.g.generate_random_irreducible (t, priv.fld, rng);
		sc.g.compute_goppa_check_matrix (sc.h, priv.fld);

		matrix subg;
		while (!sc.h.create_goppa_generator (subg, sc.hperm, rng) );
		g.set_block (subplain_size * i, subplain_size * i, subg);
	}

	//scramble matrix
	matrix S;
	S.generate_random_with_inversion (g.height(), priv.Sinv, rng);

	//scramble permutation
	permutation P;
	P.generate_random (g.width(), rng);
	P.compute_inversion (priv.Pinv);

	//public key
	pub.n = n;
	pub.t = t;
	S.mult (g);
	P.permute (S, pub.G);

	return 0;
}

int privkey::prepare ()
{
	for (uint i = 0; i < codes.size(); ++i) {
		codes[i].g.compute_goppa_check_matrix (codes[i].h, fld);
		codes[i].g.compute_square_root_matrix (codes[i].sqInv, fld);
	}
	return 0;
}

int privkey::sign (const bvector&in, bvector&out,
                   uint delta, uint attempts, prng&rng)
{
	if (in.size() != hash_size() ) return 2;
	if (!codes.size() ) return 2;

	//remove permutation
	bvector inp;
	Pinv.permute (in, inp);

	//decoding helpers
	bvector e, e2, synd, synd_orig, cw, cwc, plain, overlap;
	std::vector<uint> epos;
	permutation hpermInv;
	polynomial loc;
	uint i, t;

	uint 	mt = fld.m * codes[0].g.degree(),
	        subplain_size = fld.n - mt;

	plain.clear();

	//decode the rest
	for (uint ci = 0; ci < codes.size(); ++ci) {

		e.clear();
		e.resize (fld.n, 0);
		epos.resize (delta, 0);

		//create the codeword
		cw.clear();
		if (ci == 0)
			cw.insert (cw.end(), inp.begin(), inp.begin() + fld.n);
		else {
			cw = overlap;
			bvector::iterator tmp = inp.begin();
			tmp += (ci * subplain_size) + mt;
			cw.insert (cw.end(), tmp, tmp + subplain_size);
		}

		//create the overlap, xor it to codeword
		if (ci + 1 < codes.size() ) {
			overlap.resize (mt);
			for (uint i = 0; i < mt; ++i) overlap[i] = rng.random (2);
			cw.add_offset (overlap, subplain_size);
		}

		//compute syndrome with no extra errors
		codes[ci].hperm.compute_inversion (hpermInv);
		hpermInv.permute (cw, cwc); //canonical
		codes[ci].h.mult_vec_right (cwc, synd_orig);

		for (t = 0; t < attempts; ++t) {

			//compute syndrome with extra errors
			synd = synd_orig;
			for (i = 0; i < delta; ++i) {
				epos[i] = rng.random (fld.n);
				if (!e[epos[i]])
					synd.add (codes[ci].h[epos[i]]);
				e[epos[i]] = 1;
			}

			compute_error_locator (synd, fld,
			                       codes[ci].g,
			                       codes[ci].sqInv, loc);

			if (evaluate_error_locator_trace (loc, e2, fld) ) {
				cwc.add (e);
				cwc.add (e2);

				codes[ci].hperm.permute (cwc, cw);
				plain.insert (plain.end(), cw.begin(),
				              cw.begin() +
				              (fld.n - (fld.m *
				                        codes[ci].g.degree() ) )
				             );
				break;
			}

			for (i = 0; i < delta; ++i) {
				e[epos[i]] = 0;
			}
		}

		if (t >= attempts) //decoding failed
			return 1;

	}

	Sinv.mult_vecT_left (plain, out);

	return 0;
}

int pubkey::verify (const bvector&in, const bvector&hash, uint delta)
{
	bvector tmp;
	if (!G.mult_vecT_left (in, tmp) ) return 2; //sizing problem
	if (hash.size() != tmp.size() ) return 1; //invalid hash size

	tmp.add (hash);
	if (tmp.hamming_weight() > n * (t + delta) ) return 1; //too far
	return 0;
}
