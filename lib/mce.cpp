
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce;

int generate (pubkey&pub, privkey&priv, prng&rng)
{

	return -1; //TODO
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{

	return -1; //TODO
}

int privkey::decrypt (const bvector&in, bvector&out)
{

	return -1; //TODO
}

int privkey::sign (const bvector&in, bvector&out, uint delta, uint h, prng&rng)
{

	return -1; //TODO
}

int pubkey::verify (const bvector&in, const bvector&hash, uint delta, uint h)
{

	return -1; //TODO
}
