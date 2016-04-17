
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2016 Mirek Kratochvil <exa.exa@gmail.com>
 *
 * Codecrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Codecrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Codecrypt. If not, see <http://www.gnu.org/licenses/>.
 */

#include "polynomial.h"
#include "gf2m.h"
#include "prng.h"
#include "matrix.h"

int polynomial::degree() const
{
	int r;
	for (r = ( (int) size()) - 1; r >= 0; --r) if (item (r)) break;
	return r;
}

void polynomial::strip()
{
	resize (degree() + 1);
}

bool polynomial::zero() const
{
	for (uint i = 0; i < size(); ++i) if (item (i)) return false;
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
	if (df > degree()) resize (df + 1);
	for (int i = 0; i <= df; ++i) item (i) = fld.add (item (i), f[i]);
}

void polynomial::add_mult (const polynomial&f, uint mult, gf2m&fld)
{
	int df = f.degree();
	if (df > degree()) resize (df + 1);
	for (int i = 0; i <= df; ++i)
		item (i) = fld.add (item (i), fld.mult (mult, f[i]));
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
		if (item (d)) {
			uint t = fld.mult (item (d), hi);

			for (int i = 0; i <= df; ++i)
				item (i + d - df)
				    = fld.add (item (i + d - df),
				               fld.mult (t, f[i]));
		}
	strip();
}

void polynomial::mult (const polynomial&b, gf2m&fld)
{
	polynomial a = *this;
	int da, db, i, j;
	da = a.degree();
	db = b.degree();

	clear();
	if ( (da < 0) || (db < 0))  //multiply by zero, not much to do.
		return;

	resize (da + db + 1, 0);
	for (i = 0; i <= da; ++i)
		if (a[i]) for (j = 0; j <= db; ++j)
				item (i + j) = fld.add (item (i + j),
				                        fld.mult (a[i], b[j]));
}

polynomial polynomial::gcd (polynomial b, gf2m&fld)
{
	polynomial a = *this;

	//eukleides
	if (a.degree() < 0) return b;
	for (;;) {
		if (b.zero()) return a;
		a.mod (b, fld);
		if (a.zero()) return b;
		b.mod (a, fld);
	}
	//unreachable
	return polynomial();
}

uint polynomial::eval (uint x, gf2m&fld) const
{
	uint r = 0;
	//horner
	for (int i = degree(); i >= 0; --i)
		r = fld.add (item (i), fld.mult (r, x));
	return r;
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

void polynomial::sqrt (std::vector<polynomial>& sqInv, gf2m&fld)
{
	polynomial a = *this;
	clear();
	uint s = sqInv.size();
	resize (s, 0);

	for (uint i = 0; i < s; ++i) {
		for (uint j = 0; j < s; ++j) {
			if (j >= a.size()) break;
			if (i >= sqInv[j].size()) continue;
			item (i) = fld.add (item (i), fld.mult (sqInv[j][i], a[j]));
		}
	}
	strip();
	for (uint i = 0; i < size(); ++i)
		item (i) = fld.sq_root (item (i));
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
	while ( (t = rem.degree()) >= degd) {
		int rp = t - degd;
		if ( (int) res.size() < rp + 1) res.resize (rp + 1, 0);
		res[rp] = fld.mult (headInv, rem[t]);
		for (int i = 0; i <= degd; ++i)
			rem[i + rp] = fld.add (rem[i + rp], fld.mult (res[rp], d[i]));
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

void polynomial::ext_euclid (polynomial&a_out, polynomial&b_out,
                             polynomial&m, gf2m&fld, int deg)
{
	//TODO: speed this up (spare degree calculations)
	polynomial A, B, a, b, tmp;
	uint h;

	A = *this;
	a = m;
	B.clear();
	B.resize (1, 1);
	b.clear();

	while (a.degree() > deg) {
		if (A.degree() < 0)
			break;

		A.swap (a);
		B.swap (b);
		int j;
		while ( (j = A.degree() - a.degree()) >= 0) {
			h = fld.div (A.head(), a.head());
			tmp = a;
			tmp.shift (j);
			A.add_mult (tmp, h, fld);
			tmp = b;
			tmp.shift (j);
			B.add_mult (tmp, h, fld);
		}
	}

	a.swap (a_out);
	b.swap (b_out);
}

