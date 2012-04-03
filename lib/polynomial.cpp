
#include "codecrypt.h"

using namespace ccr;

#include <iostream>
using namespace std;
void dump (const polynomial&t)
{
	for (uint i = 0; i < t.size(); ++i) cout << t[i] << ' ';
	cout << endl;
}

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

void polynomial::add (const polynomial&f, gf2m&fld)
{
	int df = f.degree();
	if (df > degree() ) resize (df + 1);
	for (int i = 0; i <= df; ++i) item (i) = fld.add (item (i), f[i]);
}

void polynomial::mod (const polynomial&f, gf2m&fld)
{
	int df = f.degree();
	int d;
	uint hi = fld.inv (f[df]);
	// while there's place to substract, reduce by x^(d-df)-multiply of f
	for (d = degree(); d >= df; --d)
		if (item (d) ) {
			uint t = fld.mult (item (d), hi);
			for (int i = 0; i <= df; ++i)
				item (i + d - df) = fld.add (item (i + d - df),
				                             fld.mult (t, f[i]) );
		}
	strip();
}

void polynomial::mult (const polynomial&b, gf2m&fld)
{
	polynomial a = *this;
	clear();
	uint i, j, da, db;
	da = a.degree();
	db = b.degree();
	resize (da + db + 1, 0);
	for (i = 0; i <= da; ++i)
		if (a[i]) for (j = 0; j <= db; ++j)
				item (i + j) = fld.add (item (i + j),
				                        fld.mult (a[i], b[j]) );
}

polynomial polynomial::gcd (polynomial b, gf2m&fld)
{
	polynomial a = *this;

	//eukleides
	if (a.degree() < 0) return b;
	for (;;) {
		if (b.zero() ) return a;
		a.mod (b, fld);
		if (a.zero() ) return b;
		b.mod (a, fld);
	}
	//unreachable
	return polynomial();
}

bool polynomial::is_irreducible (gf2m&fld)
{
	//Ben-Or irreducibility test
	polynomial xi; //x^(2^i) in our case
	polynomial xmodf, t;

	xmodf.resize (2); //precompute (x mod f) although it is usually just x
	xmodf[0] = 0;
	xmodf[1] = 1; //x
	xi = xmodf;
	xmodf.mod (*this, fld); //mod f

	uint d = degree();
	for (uint i = 1; i <= d / 2; ++i) {
		t = xi;
		t.mult (xi, fld); //because mult would destroy xi on xi.mult(xi)
		t.mod (*this, fld);
		xi = t;
		t.add (xmodf, fld);

		t = t.gcd (*this, fld);
		if (t.degree() != 0) //gcd(f,x^2^i - x mod f) != 1
			return false;
	}
	return true;
}

void polynomial::generate_random_irreducible (uint s, gf2m&fld, prng& rng)
{
	resize (s + 1);
	item (s) = 1; //degree s
	item (0) = 1 + rng.random (fld.n - 1); //not divisible by x^1
	for (uint i = 1; i < s; ++i) item (i) = rng.random (fld.n);
	while (!is_irreducible (fld) ) {
		uint pos = rng.random (s);
		item (pos) = pos == 0 ?
		             (1 + rng.random (fld.n - 1) ) : rng.random (fld.n);
	}
}

bool polynomial::compute_square_root_matrix (vector<polynomial>&r, gf2m&fld)
{
	// step 1, generate a square matrix of squares mod poly.
	int d = degree();
	if (d < 0) return false;
	vector<polynomial>l;
	l.resize (d);
	polynomial col, t;
	for (int i = 0; i < d; ++i) {
		col.clear();
		col.resize (i + 1, 0);
		col[i] = 1;
		t = col;
		col.mult (t, fld);
		col.mod (*this, fld);
		col.resize (d, 0);
		l[i] = col;
	}
	// step 2, gauss-jordan inverse to unit matrix
	r.resize(d);
	for(int i=0;i<d;++i) {
		r[i].clear();
		r[i].resize(d,0);
		r[i][i]=1;
	}


#define add_row_mult(from,to,coeff) \
for(int c=0;c<d;++c) { \
	l[c][to]=fld.add(l[c][to],fld.mult(l[c][from],coeff));\
	r[c][to]=fld.add(r[c][to],fld.mult(r[c][from],coeff));\
}

#define row_mult(row,coeff) \
for(int c=0;c<d;++c) {\
	l[c][row]=fld.mult(l[c][row],coeff);\
	r[c][row]=fld.mult(r[c][row],coeff);\
}
	
	//gauss
	uint a;
	int i,j;
	for(i=0;i<d;++i) {
		if(l[i][i]==0) {
			//find nonzero
			for(j=i+1;j<d;++j) if(l[i][j]!=0) {
				add_row_mult(j,i,1);
				break;
			}
			if(j==d) return false;
			a=fld.inv(l[i][i]); //normalize
			row_mult(i,a);
			//zero the col
			for(j=i+1;j<d;++j) if(l[i][j]!=0) {
				a=l[i][j]; //"minus". luckily on GF(2^m) x+x=0.
				add_row_mult(i,j,a);
			}
		}
	}

	//jordan
	for(i=d-1;i>=0;--i)
		for(j=0;j<i;++j) {
			a=l[i][j];
			if(a==0) continue;
			add_row_mult(i,j,a);
		}
	return true;
}
