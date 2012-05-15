
#include "decoding.h"

void syndrome_decode (bvector&syndrome, gf2m&fld, polynomial& goppa,
                      std::vector<polynomial>& sqInv, bvector&ev)

{
	ev.clear();
	ev.resize (fld.n, 0);
	if (syndrome.zero() ) return;

	polynomial v;
	syndrome.to_poly (v, fld);

	v.inv (goppa, fld); // v=Synd^-1 mod goppa

	if (v.size() < 2) v.resize (2, 0);
	v[1] = fld.add (1, v[1]); //add x
	v.sqrt (sqInv, fld); //v = sqrt((1/s)+x) mod goppa

	polynomial a, b;
	v.mod_to_fracton (a, b, goppa, fld);

	a.square (fld);
	b.square (fld);
	b.shift (1);
	a.add (b, fld); //new a = a^2 + x b^2

	a.make_monic (fld); //now it is the error locator.

	for (uint i = 0; i < fld.n; ++i) {
		if (a.eval (i, fld) == 0) ev[i] = 1;
	}
}
