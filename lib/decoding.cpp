
#include "decoding.h"

bool syndrome_decode (bvector&syndrome, gf2m&fld, polynomial& goppa,
                      std::vector<polynomial>& sqInv, bvector&ev,
                      bool check_failure)

{
	ev.clear();
	ev.resize (fld.n, 0);
	if (syndrome.zero() ) return true;

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
		if (a.eval (i, fld) == 0) {
			ev[i] = 1;

			if (!check_failure) continue;
			//check if the error locator splits over GF(2^m).
			//We simplify it to the assumption that all roots are
			//also roots of linear factors.
			polynomial t, q, r;
			t.resize (2, 0);
			t[0] = i;
			t[1] = 1;
			a.divmod (t, q, r, fld);
			if (r.degree() >= 0) {
				ev.clear();
				return false;
			}
			a = q;
		}
	}

	return true;
}
