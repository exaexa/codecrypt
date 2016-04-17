
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

#include "decoding.h"

void compute_alternant_error_locator (polynomial&syndrome, gf2m&fld,
                                      uint t, polynomial&out)
{
	if (syndrome.zero()) {
		//ensure no roots
		out.resize (1);
		out[0] = 1;
		return;
	}

	polynomial a, b;

	polynomial x2t; //should be x^2t
	x2t.clear();
	x2t.resize (1, 1);
	x2t.shift (2 * t);

	syndrome.ext_euclid (a, b, x2t, fld, t - 1);
	uint b0inv = fld.inv (b[0]);
	for (uint i = 0; i < b.size(); ++i) b[i] = fld.mult (b[i], b0inv);
	out = b;
	//we don't care about error evaluator
}

/*
 * berlekamp trace algorithm - we puncture roots of incoming polynomial into
 * the vector of size fld.n
 *
 * Inspired by implementation from HyMES.
 */

#include <set>

bool evaluate_error_locator_trace (polynomial&sigma, bvector&ev, gf2m&fld)
{
	ev.clear();
	ev.resize (fld.n, 0);

	std::vector<polynomial> trace_aux, trace; //trace cache
	trace_aux.resize (fld.m);
	trace.resize (fld.m);

	trace_aux[0] = polynomial();
	trace_aux[0].resize (2, 0);
	trace_aux[0][1] = 1; //trace_aux[0] = x
	trace[0] = trace_aux[0]; //trace[0] = x

	for (uint i = 1; i < fld.m; ++i) {
		trace_aux[i] = trace_aux[i - 1];
		trace_aux[i].square (fld);
		trace_aux[i].mod (sigma, fld);
		trace[0].add (trace_aux[i], fld);
	}

	std::set<std::pair<uint, polynomial> > stk; //"stack"

	stk.insert (make_pair (0, sigma));

	bool failed = false;

	while (!stk.empty()) {

		uint i = stk.begin()->first;
		polynomial cur = stk.begin()->second;

		stk.erase (stk.begin());

		int deg = cur.degree();

		if (deg <= 0) continue;
		if (deg == 1) { //found a linear factor
			ev[fld.mult (cur[0], fld.inv (cur[1])) ] = 1;
			continue;
		}

		if (i >= fld.m) {
			failed = true;
			continue;
		}

		if (trace[i].zero()) {
			//compute the trace if it isn't cached
			uint a = fld.exp (i);
			for (uint j = 0; j < fld.m; ++j) {
				trace[i].add_mult (trace_aux[j], a, fld);
				a = fld.mult (a, a);
			}
		}

		polynomial t;
		t = cur.gcd (trace[i], fld);
		polynomial q, r;
		cur.divmod (t, q, r, fld);

		stk.insert (make_pair (i + 1, t));
		stk.insert (make_pair (i + 1, q));
	}

	return !failed;
}

