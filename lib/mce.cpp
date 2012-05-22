
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce;

#include "decoding.h"

int ccr::mce::generate (pubkey&pub, privkey&priv, prng&rng, uint m, uint t)
{
	//finite field
	priv.fld.create (m);

	//goppa polynomial
	priv.g.generate_random_irreducible (t, priv.fld, rng);

	//check and generator matrix
	priv.g.compute_goppa_check_matrix (priv.h, priv.fld);

	matrix generator;
	for (;;) if (priv.h.create_goppa_generator
		             (generator, priv.hperm, rng) ) break;

	//scramble matrix
	matrix S;
	S.generate_random_invertible (generator.height(), rng);
	S.compute_inversion (priv.Sinv);

	//scramble permutation
	permutation P;
	P.generate_random (generator.width(), rng);
	P.compute_inversion (priv.Pinv);

	//public key
	pub.t = t;
	S.mult (generator);
	P.permute (S, pub.G);

	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	uint s = cipher_size();
	if (t > s) return 1;
	if (in.size() != plain_size() ) return 2;

	//make a codeword
	G.mult_vecT_left (in, out);

	//add error vector
	bvector e;
	e.resize (s, 0);
	for (uint n = t; n > 0;) {
		uint p = rng.random (s);
		if (!e[p]) {
			e[p] = 1;
			--n;
		}
	}
	out.add (e);
	return 0;
}

int privkey::decrypt (const bvector&in, bvector&out)
{
	//remove the P permutation
	bvector not_permuted;
	Pinv.permute (in, not_permuted);

	//prepare for decoding
	permutation hpermInv;
	hperm.compute_inversion (hpermInv);

	bvector canonical, syndrome;
	hpermInv.permute (not_permuted, canonical);
	h.mult_vec_right (canonical, syndrome);

	//decode
	bvector ev;
	if (!syndrome_decode (syndrome, fld, g, sqInv, ev) ) {
		return 1; //if decoding somehow failed, fail as well.
	}

	// check the error vector, it should have exactly t == deg (g) errors
	if ( (int) ev.hamming_weight() != g.degree() )
		return 1;

	//correct the errors
	canonical.add (ev);

	//shuffle back into systematic order
	hperm.permute (canonical, not_permuted);

	//get rid of redundancy bits
	not_permuted.resize (Sinv.size() );

	//unscramble the result
	Sinv.mult_vecT_left (not_permuted, out);

	return 0;
}

int privkey::prepare ()
{
	g.compute_goppa_check_matrix (h, fld);
	g.compute_square_root_matrix (sqInv, fld);
	return 0;
}

int privkey::sign (const bvector&in, bvector&out, uint delta, uint attempts, prng&rng)
{
	uint i, t, s;
	bvector p, e, synd, synd2, e2;
	std::vector<uint> epos;
	permutation hpermInv;

	s = cipher_size();

	if (in.size() != s) return 2;

	//first, prepare the codeword to canonical form for decoding
	Pinv.permute (in, e2);
	hperm.compute_inversion (hpermInv);
	hpermInv.permute (e2, p);

	//prepare extra error vector
	e.resize (s, 0);
	epos.resize (delta);

	h.mult_vec_right (p, synd);

	for (t = 0; t < attempts; ++t) {
		for (i = 0; i < s; ++i) {
			epos[i] = rng.random (s);
			/* we don't care about (unlikely) error bit collisions
			   (they actually don't harm anything) */
			e[epos[i]] = 1;
		}

		//abuse linearity of p+e; it is usually faster.
		h.mult_vec_right (e, synd2);
		synd2.add (synd);

		if (syndrome_decode (synd2, fld, g, sqInv, e2) ) {
			//decoding success!
			p.add (e); //add original errors
			hperm.permute (p, e2); //back to systematic (e2~=tmp)
			Sinv.mult_vecT_left (e2, out); //get a signature
			return 0; //OK lol
		}

		//if this round failed, we try a new error pattern.

		for (i = 0; i < s; ++i) //clear the errors for the next cycle
			e[epos[i]] = 0;
	}
	return 1; //couldn't decode
}

int pubkey::verify (const bvector&in, const bvector&hash, uint delta)
{
	bvector tmp;
	if (!G.mult_vecT_left (in, tmp) ) return 2; //wrong size of input
	if (hash.size() != tmp.size() ) return 1; //wrong size of hash, not a sig.
	tmp.add (hash);
	if (tmp.hamming_weight() > (t + delta) ) return 1; //not a signature
	return 0; //sig OK
}
