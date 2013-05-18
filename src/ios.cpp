
/*
 * This file is part of Codecrypt.
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

#include "ios.h"

using namespace std;

ostream& operator<< (ostream&o, const polynomial& p)
{
	o << "polynomial degree " << p.degree() << ": ";
	for (int i = 0, e = p.degree(); i <= e; ++i) o << p[i] << ' ';
	o << endl;
	return o;
}

ostream& operator<< (ostream&o, const permutation& p)
{
	o << "permutation over " << p.size() << " elements: ";
	for (uint i = 0; i < p.size(); ++i) o << p[i] << ' ';
	o << endl;
	return o;
}

ostream& operator<< (ostream&o, const gf2m& f)
{
	o << "GF(2^" << f.m << ") of " << f.n << " elements, modulus " << f.poly << endl;
	return o;
}

ostream& operator<< (ostream&o, const matrix& m)
{
	uint i, j, h, w;
	h = m.height();
	w = m.width();
	o << "binary " << h << "x" << w << " matrix:" << endl;
	for (i = 0; i < h; ++i) {
		for (j = 0; j < w; ++j) o << m[j][i];
		o << endl;
	}
	return o;
}

ostream& operator<< (ostream&o, const bvector& v)
{
	o << "vector of " << v.size() << " elements: ";
	for (uint i = 0, e = v.size(); i < e; ++i) o << v[i];
	o << endl;
	return o;
}

