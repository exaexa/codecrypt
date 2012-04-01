
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce;

int generate (pubkey&pub, privkey&priv, prng&rng)
{

}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{

}

int privkey::decrypt (const bvector&in, bvector&out)
{

}

int privkey::sign (const bvector&in, bvector&out, uint min_delta, prng&rng)
{

}

int pubkey::verify (const bvector&in, const bvector&hash, uint missing)
{

}
