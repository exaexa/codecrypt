
#include "codecrypt.h"
using namespace ccr;

uint bvector::hamming_weight()
{
	uint r = 0;
	for (uint i = 0; i < size(); ++i) if ( (*this) [i]) ++r;
	return r;
}

void bvector::add (const bvector&a)
{
	if (a.size() > size() ) resize (a.size(), 0);
	for (uint i = 0; i < a.size(); ++i)
		item (i) = item (i) ^ a[i];
}

void bvector::add_range (const bvector&a, uint b, uint e)
{
	if (e > size() ) resize (e, 0);
	for (uint i = b; i < e; ++i)
		item (i) = item (i) ^ a[i];
}

void bvector::add_offset (const bvector&a, uint offset)
{
	if (offset + a.size() > size() ) resize (offset + a.size(), 0);
	for (uint i = 0; i < a.size(); ++i)
		item (offset + i) = item (offset + i) ^ a[i];
}

bool bvector::operator* (const bvector&a)
{
	bool r = 0;
	uint s = size(), i;
	if (s > a.size() ) s = a.size();
	for (i = 0; i < s; ++i) r ^= (item (i) &a[i]);
	return r;
}

bool bvector::zero() const
{
	for (uint i = 0; i < size(); ++i) if (item (i) ) return false;
	return true;
}

void bvector::to_poly (polynomial&r, gf2m&fld)
{
	r.clear();
	if (size() % fld.m) return; //impossible
	r.resize (size() / fld.m, 0);
	for (uint i = 0; i < size(); ++i)
		if (item (i) ) r[i/fld.m] |= (1 << (i % fld.m) );
}

void bvector::from_poly (const polynomial&r, gf2m&fld)
{
	clear();
	resize (r.size() *fld.m, 0);
	for (uint i = 0; i < size(); ++i)
		item (i) = (r[i/fld.m] >> (i % fld.m) ) & 1;
}

void bvector::to_poly_cotrace (polynomial&r, gf2m&fld)
{
	r.clear();
	if (size() % fld.m) return; //impossible
	uint s=size()/fld.m;
	r.resize (s, 0);
	for (uint i = 0; i < size(); ++i)
		if (item (i) ) r[i%s] |= (1 << (i/s) );
}

void bvector::from_poly_cotrace (const polynomial&r, gf2m&fld)
{
	clear();
	uint s=r.size();
	resize (s*fld.m, 0);
	for (uint i = 0; i < size(); ++i)
		item (i) = (r[i%s] >> (i/s) ) & 1;
}

/*
 * utility colex (un)ranking for niederreiter and workalikes.
 * see Ruskey's Combinatorial Generation, algorithm 4.10
 *
 * TODO use (external) cache for combination numbers to speed this up.
 */

#include <gmp.h>

static void combination_number (uint n, uint k, mpz_t& r)
{
	mpz_t t;
	if (k > n) {
		mpz_set_ui (r, 0);
		return;
	}

	if (k * 2 > n) k = n - k;

	mpz_set_ui (r, 1);
	mpz_init (t);

	//upper part n*(n-1)*(n-2)*...*(n-k+1)
	for (uint i = n; i > n - k; --i) {
		mpz_swap (t, r);
		mpz_mul_ui (r, t, i);
	}
	//lower part (div k!)
	for (uint i = k; i > 1; --i) {
		mpz_swap (t, r);
		mpz_tdiv_q_ui (r, t, i);
	}

	mpz_clear (t);
}

static void bvector_to_mpz (bvector&v, mpz_t&r)
{
	mpz_set_ui (r, 0);
	mpz_realloc2 (r, v.size() );
	for (uint i = 0; i < v.size(); ++i)
		if (v[i])
			mpz_setbit (r, i);
		else	mpz_clrbit (r, i);
}

static void mpz_to_bvector (mpz_t&x, bvector&r)
{
	r.resize (mpz_sizeinbase (x, 2) );
	for (uint i = 0; i < r.size(); ++i)
		r[i] = mpz_tstbit (x, i);
}

void bvector::colex_rank (bvector&r)
{
	mpz_t res, t, t2;
	mpz_init_set_ui (res, 0);
	mpz_init (t);
	mpz_init (t2);

	uint i, j;
	j = 1;
	for (i = 0; i < size(); ++i)
		if (item (i) ) {
			combination_number (i, j, t);
			mpz_swap (t2, res);
			mpz_add (res, t, t2);
			++j;
		}

	mpz_to_bvector (res, r);

	mpz_clear (t);
	mpz_clear (t2);
	mpz_clear (res);
}

#include <stdio.h>
void bvector::colex_unrank (bvector&res, uint n, uint k)
{
	mpz_t r, t, t2;
	mpz_init (r);
	mpz_init (t);
	mpz_init (t2);

	bvector_to_mpz (*this, r);

	res.clear();
	res.resize (n, 0);

	uint p;
	for (uint i = k; i > 0; --i) {
		p = i;
		for (;;) {
			combination_number (p, i, t);

			if (mpz_cmp (t, r) > 0) break;
			++p;
		}

		combination_number (p - 1, i, t);
		mpz_swap (t2, r);
		mpz_sub (r, t2, t);
		if (p > n) continue; //overflow protection
		res[p-1] = 1;
	}

	mpz_clear (r);
	mpz_clear (t);
	mpz_clear (t2);
}
