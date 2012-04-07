
#include "codecrypt.h"

#include <iostream>
using namespace std;
using namespace ccr;

ostream& operator<< (ostream&o, const polynomial& p)
{
	o << "polynomial degree " << p.degree() << ':' << endl;
	for (int i = 0, e = p.degree(); i <= e; ++i) o << p[i] << ' ';
	o << endl;
	return o;
}

ostream& operator<< (ostream&o, const permutation& p)
{
	o << "permutation over " << p.size() << " elements:" << endl;
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
	o << "vector of " << v.size() << " elements:" << endl;
	for (uint i = 0, e = v.size(); i < e; ++i) cout << v[i];
	cout << endl;
	return o;
}

