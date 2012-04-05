
#include "codecrypt.h"

#include <stdlib.h>
#include <time.h>

#include <iostream>
using namespace std;

ostream& operator<< (ostream&o, ccr::polynomial p)
{
	o << "polynomial degree " << p.degree() << ':' << endl;
	for (int i = 0, e = p.degree(); i <= e; ++i) o << p[i] << ' ';
	o << endl;
	return o;
}

ostream& operator<< (ostream&o, ccr::permutation p)
{
	o << "permutation over " << p.size() << " elements:" << endl;
	for (uint i = 0; i < p.size(); ++i) o << p[i] << ' ';
	o << endl;
	return o;
}

ostream& operator<< (ostream&o, ccr::gf2m f)
{
	o << "GF(2^" << f.m << ") of " << f.n << " elements, modulus " << f.poly << endl;
	return o;
}

ostream& operator<< (ostream&o, ccr::matrix m)
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

class primitiverng : public ccr::prng
{
public:
	uint random (uint n) {
		return rand() % n;
	}

	void seed (uint n) {
		srand (time (NULL) + n);
	}
};

int main()
{
	primitiverng r;
	r.seed (0);

	ccr::mce::privkey priv;
	ccr::mce::pubkey pub;
	ccr::mce::generate (pub, priv, r, 9, 15);

	cout << "PRIVATE KEY" << endl;
	cout << priv.fld;
	cout << priv.hperm;
	cout << priv.Pinv;
	cout << priv.Sinv;
	cout << priv.g;
	cout << "PUBLIC KEY" << endl;
	cout << pub.t << endl;
	cout << pub.G;

	return 0;
}

