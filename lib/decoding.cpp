
#include "decoding.h"

void compute_error_locator (bvector&syndrome, gf2m&fld, polynomial& goppa,
                            std::vector<polynomial>& sqInv, polynomial&out)
{
	if (syndrome.zero() ) {
		//ensure no roots
		out.resize (1);
		out[0] = 1;
		return;
	}

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
	out = a;
}

bool evaluate_error_locator_dumb (polynomial&a, bvector&ev, gf2m&fld)
{
	ev.clear();
	ev.resize (fld.n, 0);

	for (uint i = 0; i < fld.n; ++i) {
		if (a.eval (i, fld) == 0) {
			ev[i] = 1;

			//divide the polynomial by (found) linear factor
			polynomial t, q, r;
			t.resize (2, 0);
			t[0] = i;
			t[1] = 1;
			a.divmod (t, q, r, fld);

			//if it doesn't divide, die.
			if (r.degree() >= 0) {
				ev.clear();
				return false;
			}
			a = q;
		}
	}

	//also if there's something left, die.
	if (a.degree() > 0) {
		ev.clear();
		return false;
	}

	return true;
}
