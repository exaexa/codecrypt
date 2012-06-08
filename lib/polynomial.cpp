
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
	return (item (0) == 1) ? true : false;
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
				item (i + d - df)
				= fld.add (item (i + d - df),
				           fld.mult (t, f[i]) );
		}
	strip();
}

void polynomial::mult (const polynomial&b, gf2m&fld)
{
	polynomial a = *this;
	uint i, j;
	int da, db;
	da = a.degree();
	db = b.degree();

	clear();
	if ( (da < 0) || (db < 0) ) //multiply by zero
		return;

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
	if (d < 0) return false;
	for (uint i = 1; i <= (d / 2); ++i) {
		for (uint j = 0; j < fld.m; ++j) {
			t = xi;
			t.mult (xi, fld);
			t.mod (*this, fld);
			xi.swap (t);
		}
		t = xi;
		t.add (xmodf, fld);

		t = t.gcd (*this, fld);
		if (t.degree() > 0)
			return false;
	}
	return true;
}

void polynomial::generate_random_irreducible (uint s, gf2m&fld, prng& rng)
{
	resize (s + 1);
	item (s) = 1; //degree s
	for (uint i = 0; i < s; ++i) item (i) = rng.random (fld.n);
	while (!is_irreducible (fld) )
		item (rng.random (s) ) = rng.random (fld.n);
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
		}
		a = fld.inv (l[i][i]); //normalize
		row_mult (i, a);
		//zero the col
		for (j = i + 1; j < d; ++j)
			if (l[i][j] != 0) {
				a = l[i][j]; //"minus". luckily on GF(2^m) x+x=0.
				add_row_mult (i, j, a);
			}
	}
	//jordan
	for (i = d - 1; i >= 0; --i) {
		for (j = 0; j < i; ++j) {
			a = l[i][j];
			if (a == 0) continue;
			add_row_mult (i, j, a);
		}
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

	r.resize (fld.n);

	for (uint i = 0; i < fld.n; ++i) {
		polynomial col;
		col.resize (2);
		col[0] = i;
		col[1] = 1;
		col.inv (*this, fld);
		//i-th row of the check matrix is polynomial 1/(x-i)
		r[i].from_poly (col, fld);
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
	mult (a, fld);
}

void polynomial::sqrt (vector<polynomial>& sqInv, gf2m&fld)
{
	polynomial a = *this;
	clear();
	uint s = sqInv.size();
	resize (s, 0);

	for (uint i = 0; i < s; ++i) {
		for (uint j = 0; j < s; ++j) {
			if (j >= a.size() ) break;
			if (i >= sqInv[j].size() ) continue;
			item (i) = fld.add (item (i), fld.mult (sqInv[j][i], a[j]) );
		}
	}
	strip();
	for (uint i = 0; i < size(); ++i)
		item (i) = fld.sq_root (item (i) );
}

void polynomial::div (polynomial&p, polynomial&m, gf2m&fld)
{
	polynomial r0, r1, s0, s1, s2, q0, q1;

	r0 = m;
	r1 = p;
	r1.mod (m, fld);

	s0.clear();

	s1.swap (*this);
	s1.mod (m, fld);

	while (r1.degree() >= 0) {
		r0.divmod (r1, q0, q1, fld);
		r0.swap (r1);
		r1.swap (q1);

		s2 = s0;
		q0.mult (s1, fld);
		q0.mod (m, fld);
		s2.add (q0, fld);

		s0.swap (s1);
		s1.swap (s2);
	}

	this->swap (s0);

	//scalar divide by r0 head
	if (r0.degree() < 0) return;
	uint c = r0[r0.degree() ];
	c = fld.inv (c);
	for (uint i = 0; i < size(); ++i) item (i) = fld.mult (item (i), c);
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
	rem.strip();
}

void polynomial::inv (polynomial&m, gf2m&fld)
{
	polynomial a = *this;
	resize (1);
	item (0) = 1;
	div (a, m, fld);
}

void polynomial::mod_to_fracton (polynomial&a, polynomial&b,
                                 polynomial&m, gf2m&fld)
{
	int deg = m.degree() / 2;
	polynomial a0, a1, b0, b1, q, r;
	a0 = m;
	a1 = *this;
	a1.mod (m, fld);

	b0.clear();
	b1.clear();
	b1.resize (1, 1);

	while (a1.degree() > deg) {

		a0.divmod (a1, q, r, fld);
		a0.swap (a1);
		a1.swap (r);

		q.mult (b1, fld);
		q.mod (m, fld);
		q.add (b0, fld);
		b0.swap (b1);
		b1.swap (q);
	}
	a.swap (a1);
	b.swap (b1);
}
