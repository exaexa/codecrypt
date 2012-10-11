
#include "fwht.h"

#include <vector>
using namespace std;

/*
 * we count on that all integers are sufficiently large.
 * They should be, largest value occuring should be O(k*n) if initial vector is
 * consisted only from {0,1}^n, and we don't usually have codes of this size.
 */

static void fwht (vector<int> x, vector<int>&r)
{
	int bs, s;
	s = x.size();
	r.resize (s);
	bs = s >> 1;
	r.swap (x);
	while (bs) {
		x.swap (r);
		for (uint i = 0; i < s; ++i) {
			if ( (i / bs) & 1)
				r[i] = x[i-bs] - x[i];
			else
				r[i] = x[i] + x[i+bs];
		}
		bs >>= 1;
	}
}

//we expect correct parameter size and preallocated out.
void fwht_dyadic_multiply (const bvector& a, const bvector& b, bvector& out)
{

	//lift everyting to Z.
	vector<int> t, A, B;
	uint i;

	t.resize (a.size() );
	A.resize (a.size() );
	B.resize (a.size() );

	for (i = 0; i < a.size(); ++i) t[i] = a[i];
	fwht (t, A);

	for (i = 0; i < b.size(); ++i) t[i] = b[i];
	fwht (t, B);

	//multiply diagonals to A
	for (i = 0; i < A.size(); ++i) A[i] *= B[i];
	fwht (A, t);

	uint bitpos = a.size(); //no problem as a.size() == 1<<m == 2^m
	for (i = 0; i < t.size(); ++i) out[i] = (t[i] & bitpos) ? 1 : 0;
}

