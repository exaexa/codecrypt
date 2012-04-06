
#include "codecrypt.h"

using namespace ccr;

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

void polynomial::add_mult (const polynomial&f, uint mult, gf2m&fld)
{
	int df = f.degree();
	if (df > degree() ) resize (df + 1);
	for (int i = 0; i <= df; ++i)
		item (i) = fld.add (item (i), fld.mult (mult, f[i]) );
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

bool polynomial::is_irreducible (gf2m&fld) const
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
		if (t.degree() > 0) //gcd(f,x^2^i - x mod f) is polynomial
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
	r.resize (d);
	for (int i = 0; i < d; ++i) {
		r[i].clear();
		r[i].resize (d, 0);
		r[i][i] = 1;
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
	int i, j;
	for (i = 0; i < d; ++i) {
		if (l[i][i] == 0) {
			//find nonzero
			for (j = i + 1; j < d; ++j) if (l[i][j] != 0) {
					add_row_mult (j, i, 1);
					break;
				}
			if (j == d) return false;
			a = fld.inv (l[i][i]); //normalize
			row_mult (i, a);
			//zero the col
			for (j = i + 1; j < d; ++j) if (l[i][j] != 0) {
					a = l[i][j]; //"minus". luckily on GF(2^m) x+x=0.
					add_row_mult (i, j, a);
				}
		}
	}

	//jordan
	for (i = d - 1; i >= 0; --i)
		for (j = 0; j < i; ++j) {
			a = l[i][j];
			if (a == 0) continue;
			add_row_mult (i, j, a);
		}
	return true;
}

uint polynomial::eval (uint x, gf2m&fld) const
{
	uint r = 0;
	//horner
	for (int i = degree(); i >= 0; --i)
		r = fld.add (item (i), fld.mult (r, x) );
	return r;
}

void polynomial::compute_goppa_check_matrix (matrix&r, gf2m&fld)
{
	if (degree() < 0) return; //wrongly initialized polynomial
	uint t = degree();
	vector<vector<uint> > yz, h;
	uint i, j, k;
	yz.resize (t);
	h.resize (t);
	for (i = 0; i < t; ++i) {
		yz[i].resize (fld.n);
		h[i].resize (fld.n, 0);
	}
	//create Y*Z
	for (i = 0; i < fld.n; ++i) yz[0][i] = fld.inv (eval (i, fld) );
	for (i = 1; i < t; ++i) for (j = 0; j < fld.n; ++j)
			yz[i][j] = fld.mult (yz[i-1][j], j);
	//X*Y*Z = h
	for (i = 0; i < t; ++i)
		for (j = 0; j < fld.n; ++j)
			for (k = 0; k <= i; ++k)
				h[i][j] = fld.add (h[i][j], fld.mult
				                   (yz[k][j],
				                    item (t + k - i) ) );

	//now convert to binary
	r.resize (fld.n);
	for (i = 0; i < fld.n; ++i) {
		r[i].resize (fld.m * t, 0);
		for (j = 0; j < fld.m * t; ++j)
			r[i][j] = (h[j/fld.m][i] >> (j % fld.m) ) & 1;
	}
}

void polynomial::make_monic (gf2m&fld)
{
	int d = degree();
	if (d < 0) return;
	uint m = fld.inv (item (d) );
	for (uint i = 0; i <= d; ++i) item (i) = fld.mult (item (i), m);
}

void polynomial::shift (uint n)
{
	if (degree() < 0) return;
	insert (begin(), n, 0);
}

void polynomial::square (gf2m&fld)
{
	polynomial a = *this;
	this->mult (a, fld);
}

void polynomial::sqrt (vector<polynomial>& sqInv, gf2m&fld)
{
	polynomial a = *this;
	clear();
	for (uint i = 0; i < a.size(); ++i) add_mult (sqInv[i], a[i], fld);
	for (uint i = 0; i < size(); ++i) item (i) = fld.sq_root (item (i) );
}

void polynomial::div (polynomial&p, polynomial&m, gf2m&fld)
{
	int degp = p.degree();
	if (degp < 0) return;

	uint headInv = fld.inv (p[degp]);
	polynomial A = *this;
	A.mod (m, fld);
	clear();
	int da;
	while ( (da = A.degree() ) >= degp) {
		int rp = da - degp;
		if (size() < rp + 1) resize (rp + 1, 0);
		item (rp) = fld.mult (headInv, A[da]);
		for (uint i = 0; i <= degp; ++i)
			A[i+rp] = fld.add (A[i+rp], fld.mult (item (rp), p[i]) );
	}
}

void polynomial::divmod (polynomial&d, polynomial&res, polynomial&rem, gf2m&fld)
{
	int degd = d.degree();
	if (degd < 0) return;

	uint headInv = fld.inv (d[degd]);
	rem = *this;
	res.clear();
	int t;
	while ( (t = rem.degree() ) >= degd) {
		int rp = t - degd;
		if (res.size() < rp + 1) res.resize (rp + 1, 0);
		res[rp] = fld.mult (headInv, rem[t]);
		for (uint i = 0; i <= degd; ++i)
			rem[i+rp] = fld.add (rem[i+rp], fld.mult (res[rp], d[i]) );
	}
}

void polynomial::inv (polynomial&m, gf2m&fld)
{
	polynomial a = *this;
	this->resize (2);
	item (0) = 0;
	item (1) = 1;
	div (a, m, fld);
}

void polynomial::mod_to_fracton (polynomial&a, polynomial&b, polynomial&m, gf2m&fld)
{
	int deg = m.degree() / 2;
	polynomial a0, a1, b0, b1, t1, t2;
	a0 = m;
	a0.make_monic (fld);
	a1 = *this;
	a1.mod (m, fld);
	b0.resize (1, 0);
	b1.resize (1, 1);
	while (a1.degree() > deg) {

		a0.divmod (a1, t1, t2, fld);
		a0.swap (a1);
		a1.swap (t2);

		t1.mult (b1);
		t1.mod (m);
		t1.add (b0);
		b0.swap (b1);
		b1.swap (t1);
	}
	a = a1;
	b = b1;
}
