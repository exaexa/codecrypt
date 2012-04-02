
#include "codecrypt.h"

using namespace ccr;

#if 0
#include <iostream>
using namespace std;
void dump (const polynomial&t)
{
	for (uint i = 0; i < t.size(); ++i) cout << t[i];
	cout << endl;
}
#endif

int polynomial::degree() const
{
	int r = -1;
	for (uint i = 0; i < size(); ++i) if (item (i) ) r = i;
	return r;
}

void polynomial::strip()
{
	resize (degree() + 1);
}

bool polynomial::zero() const
{
	for (uint i = 0; i < size(); ++i) if (item (i) ) return false;
	return true;
}

void polynomial::add (const polynomial&f)
{
	int df = f.degree();
	if (df > degree() ) resize (df + 1);
	for (int i = 0; i <= df; ++i) item (i) = item (i) ^ f[i];
}

void polynomial::mod (const polynomial&f)
{
	int df = f.degree();
	int d;
	// while there's place to substract, reduce by x^(d-df)-multiply of f
	while ( (d = degree() ) >= df) {
		for (int i = 0; i <= df; ++i)
			item (i + d - df) = item (i + d - df) ^ f[i];
	}
	strip();
}

void polynomial::mult (const polynomial&b)
{
	polynomial a = *this;
	clear();
	uint i, j, da, db;
	da = a.degree();
	db = b.degree();
	resize (da + db + 1, 0);
	for (i = 0; i <= da; ++i)
		if (a[i]) for (j = 0; j <= db; ++j)
				item (i + j) = item (i + j) ^ b[j];
}

polynomial polynomial::gcd (polynomial b)
{
	polynomial a = *this;

	//eukleides
	if (a.degree() < 0) return b;
	for (;;) {
		if (b.zero() ) return a;
		a.mod (b);
		if (a.zero() ) return b;
		b.mod (a);
	}
	//unreachable
	return polynomial();
}

bool polynomial::is_irreducible()
{
	//Ben-Or irreducibility test
	polynomial xi; //x^(2^i) in our case
	polynomial xmodf, t;

	xmodf.resize (2); //precompute (x mod f) although it is usually just x
	xmodf[0] = 0;
	xmodf[1] = 1; //x
	xi = xmodf;
	xmodf.mod (*this); //mod f

	uint n = degree();
	for (uint i = 1; i <= n / 2; ++i) {
		t = xi;
		t.mult (xi); //because mult would destroy xi on xi.mult(xi)
		t.mod (*this);
		xi = t;
		t.add (xmodf);

		t = t.gcd (*this);
		if (t.degree() != 0) //gcd(f,x^2^i - x mod f) != 1
			return false;
	}
	return true;
}

void polynomial::generate_random_irreducible (uint s, prng & rng)
{
	resize (s + 1);
	item (s) = 1; //degree s
	item (0) = 1; //not divisible by x^1
	for (uint i = 1; i < s; ++i) item (i) = rng.random (2);
	while (!is_irreducible() ) {
		uint pos = 1 + rng.random (s - 1);
		item (pos) = !item (pos);
	}
}

void polynomial::compute_mod_squaring_matrix (matrix&r)
{
	int d = degree();
	if (d < 0) return;
	r.resize (d);
	polynomial col, t;
	for (int i = 0; i < d; ++i) {
		col.clear();
		col.resize (i + 1, 0);
		col[i] = 1;
		t = col;
		col.mult (t);
		col.mod (*this);
		col.resize (d, 0);
		r[i] = col;
	}
}
