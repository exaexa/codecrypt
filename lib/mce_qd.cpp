
#include "codecrypt.h"

using namespace ccr;
using namespace ccr::mce_qd;

#include "decoding.h"

int mce_qd::generate (pubkey&pub, privkey&priv, prng&rng, uint m, uint t)
{
	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	uint s = cipher_size();
	if (t > s) return 1;
	if (in.size() != plain_size() ) return 2;

	return 0;
}

int privkey::decrypt (const bvector&in, bvector&out)
{
	if (in.size() != cipher_size() ) return 2;

	return 0;
}

int privkey::prepare ()
{
	return 0;
}

