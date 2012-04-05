
#include "codecrypt.h"

using namespace ccr;

void permutation::compute_inversion (permutation&r) const
{
	r.resize (size(), 0);
	for (uint i = 0; i < size(); ++i)
		r[item (i) ] = i;
}

void permutation::generate_random (uint size, prng&rng)
{
	resize (size, 0);
	uint i;
	for (i = 0; i < size; ++i) item (i) = i;

	//knuth shuffle
	for (i = size - 1; i > 0; --i) {
		uint j = rng.random (i + 1);
		if (i != j) {
			uint t = item (i);
			item (i) = item (j);
			item (j) = t;
		}
	}
}

void permutation::permute (const bvector&a, bvector&r) const
{
	r.resize (a.size() );
	for (uint i = 0; i < size(); ++i) r[item (i) ] = a[i];
}

void permutation::permute (const matrix&a, matrix&r) const
{
	r.resize (a.size() );
	for (uint i = 0; i < size(); ++i) r[item (i) ] = a[i];
}

void permutation::permute_rows (const matrix&a, matrix&r) const
{
	r.resize (a.size() );
	for (uint i = 0; i < a.size(); ++i) permute (a[i], r[i]);
}

