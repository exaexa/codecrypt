
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

bool polynomial::one() const
{
	if (degree() != 0) return false;
	return item (0) == 1;
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
	if (df < 0) { //mod 0 -> 0
		clear();
		return;
	}
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
	uint i, j;
	int da, db;
	da = a.degree();
	db = b.degree();
	if ( (da < 0) || (db < 0) ) { //multiply by zero
		clear();
		return;
	}

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
		for (uint j = 0; j < fld.m; ++j) {
			t = xi;
			t.mult (xi, fld);
			t.mod (*this, fld);
			xi.swap (t);
		}
		t = xi;
		t.add (xmodf, fld);

		t = t.gcd (*this, fld);
		if (t.degree() > 0) //gcd(f,x^2^i - x mod f) != const
			return false;
	}
	return true;
}

void polynomial::generate_random_irreducible (uint s, gf2m&fld, prng& rng)
{
	resize (s + 1);
	item (s) = 1; //degree s
	item (0) = 1 + rng.random (fld.n - 1);
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
	vector<vector<uint> > vd, h;
	uint i, j, k;

	//construction from Barreto's slides with maximal support L=[0..fld.n)
	vd.resize (fld.n);
	for (i = 0; i < fld.n; ++i) {
		vd[i].resize (t);
		vd[i][0] = fld.inv (eval (i, fld) );
	}
	//compute support powers
	for (j = 0; j < fld.n; ++j) for (i = 1; i < t; ++i)
			vd[j][i] = fld.mult (vd[j][i-1], j);

	//multiply by goppa coefficients (compute t*vd)
	h.resize (fld.n);
	for (i = 0; i < fld.n; ++i) {
		h[i].resize (t, 0);
		for (j = 0; j < t; ++j) //computing the element h[i][j]
			for (k = 0; k <= j; ++k) //k = column index of t
				h[i][j] = fld.add (h[i][j],
				                   fld.mult (item (t - j + k),
				                             vd[i][k]) );
	}

	//now convert to binary
	r.resize (fld.n);
	for (i = 0; i < fld.n; ++i) {
		r[i].resize (fld.m * t);
		for (j = 0; j < fld.m * t; ++j)
			r[i][j] = (h[i][j/fld.m] >> (j % fld.m) ) & 1;
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
	polynomial r0, r1, s0, s1, s2, q1, q2;

	r0 = m;
	r1 = p;
	r1.mod (m, fld);

	s0.clear();

	s1 = *this;
	s1.mod (m, fld);

	while (r1.degree() >= 0) {
		r0.divmod (r1, q1, q2, fld);
		r0.swap (r1);
		r1.swap (q2);

		s2 = s0;
		q1.mult (s1, fld);
		q1.mod (m, fld);
		s2.add (q1, fld);

		s0.swap (s1);
		s1.swap (s2);
	}

	*this = s0;
	if (r0.degree() >= 0) {
		uint m = fld.inv (r0[r0.degree() ]);
		for (uint i = 0; i < size(); ++i) item (i) = fld.mult (item (i), m);
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
	a1 = *this;
	a1.mod (m, fld);
	b0.resize (1, 0);
	b1.resize (1, 1);
	while (a1.degree() > deg) {

		a0.divmod (a1, t1, t2, fld);
		a0.swap (a1);
		a1.swap (t2);

		t1.mult (b1, fld);
		t1.mod (m, fld);
		t1.add (b0, fld);
		b0.swap (b1);
		b1.swap (t1);
	}
	a = a1;
	b = b1;
}
