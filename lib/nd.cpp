
#include "codecrypt.h"

#include "decoding.h"

using namespace ccr;
using namespace ccr::nd;

int nd::generate (pubkey&pub, privkey&priv, prng&rng, uint m, uint t)
{
	//galois field
	priv.fld.create (m);

	//goppa polynomial
	priv.g.generate_random_irreducible (t, priv.fld, rng);

	matrix h;
	priv.g.compute_goppa_check_matrix (h, priv.fld);

	//scrambler
	matrix S;
	S.generate_random_invertible (h.height(), rng);
	S.compute_inversion (priv.Sinv);

	//permutation
	priv.Pinv.generate_random (h.width(), rng);

	/*
	 * note: we actually don't need the inversion, as it inverts itself
	 * when permuting SH to pubkey.
	 */

	//pubkey
	pub.t = t;
	S.mult (h);
	priv.Pinv.permute (S, pub.H);

	return 0;
}

int privkey::prepare ()
{
	g.compute_square_root_matrix (sqInv, fld);
	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out)
{
	if (in.size() != plain_size() ) return 1;
	H.mult_vec_right (in, out);
	return 0;
}

int privkey::decrypt (const bvector&in, bvector&out)
{
	if (in.size() != cipher_size() ) return 2;

	bvector unsc; //unscrambled
	Sinv.mult_vec_right (in, unsc);

	polynomial loc;
	compute_error_locator (unsc, fld, g, sqInv, loc);

	bvector ev;
	if (!evaluate_error_locator_dumb (loc, ev, fld) )
		return 1;

	if ( (int) ev.hamming_weight() != g.degree() )
		return 1;

	Pinv.permute (ev, out);
	return 0;
}

int privkey::sign (const bvector&in, bvector&out, uint delta, uint attempts, prng&rng)
{
	uint i, s, t;

	bvector synd_unsc, synd, e;

	polynomial loc;

	s = hash_size();
	if (in.size() != s) return 2;

	for (t = 0; t < attempts; ++t) {

		synd = in;
		for (i = 0; i < delta; ++i) {
			uint pos = rng.random (s);
			synd[pos] = !synd[pos]; //flip a bit
		}

		Sinv.mult_vec_right (synd, synd_unsc);

		compute_error_locator (synd_unsc, fld, g, sqInv, loc);

		if (evaluate_error_locator_dumb (loc, e, fld) ) {

			Pinv.permute (e, out);
			return 0;
		}
	}

	return 1;
}

int pubkey::verify (const bvector&in, const bvector&hash, uint delta)
{
	bvector tmp;
	if (!H.mult_vec_right (in, tmp) ) return 2;
	if (hash.size() != tmp.size() ) return 1;
	tmp.add (hash);
	if (tmp.hamming_weight() > delta) return 1;
	return 0;
}
