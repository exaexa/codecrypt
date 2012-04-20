
#include "decoding.h"

void syndrome_decode (bvector&syndrome, gf2m&fld, polynomial& goppa,
                      std::vector<polynomial>& sqInv, bvector&ev)

{
	ev.clear();
	ev.resize (fld.n, 0);
	if (syndrome.zero() ) return;

	polynomial p;
	syndrome.to_poly (p, fld);
	p.inv (goppa, fld); // p=S^-1 mod goppa

	p[1] = fld.add (1, p[1]); //p is now tau
	p.sqrt (sqInv, fld); //tau = sqrt(T+x) mod goppa

	polynomial a, b;
	p.mod_to_fracton (a, b, goppa, fld);
	a.square (fld);
	b.square (fld);
	b.shift (1);
	a.add (b, fld); //new a = a^2 + x b^2

	a.make_monic (fld); //now it is the error locator.

	for (uint i = 0; i < fld.n; ++i) {
		if (0 == a.eval (i, fld) ) ev[i] = 1;
	}
}
