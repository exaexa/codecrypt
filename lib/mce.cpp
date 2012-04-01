
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

int privkey::sign (const bvector&in, bvector&out, uint min_delta, prng&rng)
{

	return -1; //TODO
}

int pubkey::verify (const bvector&in, const bvector&hash, uint missing)
{

	return -1; //TODO
}
