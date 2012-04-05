
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce;

int ccr::mce::generate (pubkey&pub, privkey&priv, prng&rng, uint m, uint t)
{
	//finite field
	priv.fld.create (m);

	//goppa polynomial
	priv.g.generate_random_irreducible (t, priv.fld, rng);

	//check and generator matrix
	matrix generator;
	permutation hp;
	priv.g.compute_goppa_check_matrix (priv.h, priv.fld);

	int attempts_left = 1 << m;
	for (;;) {
		if (priv.h.create_goppa_generator (generator, hp, rng) ) break;
		--attempts_left;
	}
	if (!attempts_left) return 1;

	hp.compute_inversion (priv.hperm);

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

	return -1; //TODO
}

int privkey::decrypt (const bvector&in, bvector&out)
{

	return -1; //TODO
}

int privkey::prepare ()
{
	g.compute_goppa_check_matrix (h, fld);
	g.compute_square_root_matrix (sqInv, fld);
	return 0;
}

int privkey::sign (const bvector&in, bvector&out, uint delta, uint h, prng&rng)
{

	return -1; //TODO
}

int pubkey::verify (const bvector&in, const bvector&hash, uint delta, uint h)
{

	return -1; //TODO
}
