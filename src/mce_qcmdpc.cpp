
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

#include "mce_qcmdpc.h"

#include "gf2m.h"
#include "polynomial.h"

using namespace mce_qcmdpc;

int mce_qcmdpc::generate (pubkey&pub, privkey&priv, prng&rng,
                          uint block_size, uint block_count, uint wi,
                          uint t, uint rounds, uint delta)
{
	uint i, j;
	priv.H.resize (block_count);

	if (wi > block_size / 2) return 1; //safety

	/*
	 * Trick. Cyclomatic matrix of size n is invertible if a
	 * polynomial that's made up from its first row is coprime to
	 * (x^n-1), the polynomial inversion and matrix inversion are
	 * then isomorphic.
	 */
	gf2m gf;
	gf.create (1); //binary
	polynomial xmm1; //x^m-1
	xmm1.resize (block_size + 1, 0);
	xmm1[0] = 1;
	xmm1[block_size] = 1;
	polynomial last_inv_H;
	for (;;) {
		//retry generating the rightmost block until it is invertible
		polynomial g;
		g.resize (block_size, 0);
		for (i = 0; i < wi; ++i)
			for (uint pos = rng.random (block_size);
			     g[pos] ? 1 : (g[pos] = 1, 0);
			     pos = rng.random (block_size));

		//try if it is coprime to (x^n-1)
		polynomial gcd = g.gcd (xmm1, gf);
		if (!gcd.one()) continue; //it isn't.

		//if it is, save it to matrix (in "reverse" order for columns)
		priv.H[block_count - 1].resize (block_size, 0);
		for (i = 0; i < block_size && i < g.size(); ++i)
			priv.H[block_count - 1][i] = g[ (-i) % block_size];

		//invert it, save for later and succeed.
		g.inv (xmm1, gf);
		last_inv_H = g;
		break;
	}

	//generate the rests of matrix blocks, fill the G right away.
	pub.G.resize (block_count - 1);
	for (i = 0; i < block_count - 1; ++i) {
		polynomial hi;
		hi.resize (block_size, 0);

		//generate the polynomial corresponding to the first row
		for (j = 0; j < wi; ++j)
			for (uint pos = rng.random (block_size);
			     hi[pos] ? 1 : (hi[pos] = 1, 0);
			     pos = rng.random (block_size));
		//save it to H
		priv.H[i].resize (block_size);
		for (j = 0; j < block_size; ++j) priv.H[i][j] = hi[ (-j) % block_size];

		//compute inv(H[last])*H[i]
		hi.mult (last_inv_H, gf);
		hi.mod (xmm1, gf);
		//save it to G
		pub.G[i].resize (block_size);
		for (j = 0; j < block_size; ++j) pub.G[i][j] = hi[j % block_size];
	}

	//save the target params
	pub.t = priv.t = t;
	priv.rounds = rounds;
	priv.delta = delta;

	return 0;
}

int privkey::prepare()
{
	return 0;
}

int pubkey::encrypt (const bvector& in, bvector&out, prng&rng)
{
	uint s = cipher_size();

	if (t > s) return 1;

	//create the error vector
	bvector e;
	e.resize (s);
	for (uint i = 0; i < t; ++i)
		for (uint pos = rng.random (s);
		     e[pos] ? 1 : (e[pos] = 1, 0);
		     pos = rng.random (s));

	return encrypt (in, out, e);
}

int pubkey::encrypt (const bvector&in, bvector&out, const bvector&errors)
{

	uint ps = plain_size();
	if (in.size() != ps) return 1;
	uint bs = G[0].size();
	for (uint i = 1; i < G.size(); ++i) if (G[i].size() != bs) return 1; //prevent mangled keys

	//first, the checksum part
	bvector bcheck;

	//G stores first row(s) of the circulant matrix blocks, proceed row-by-row and construct the checkum
	for (uint i = 0; i < ps; ++i)
		if (in[i]) bcheck.rot_add (G[ (i % ps) / bs], i % bs);

	//compute the ciphertext
	out = in;
	out.append (bcheck);
	out.add (errors);

	return 0;
}

int privkey::decrypt (const bvector & in, bvector & out)
{
	bvector tmp_errors;
	return decrypt (in, out, tmp_errors);
}

#include <vector>

int privkey::decrypt (const bvector & in_orig, bvector & out, bvector & errors)
{
	uint i;
	uint cs = cipher_size();

	if (in_orig.size() != cs) return 1;
	uint bs;
	bs = H[0].size();

	/*
	 * probabilistic decoding!
	 */

	//compute the syndrome first
	bvector syndrome;
	syndrome.resize (bs, 0);
	bvector in = in_orig; //we will modify it

	for (i = 0; i < cs; ++i) if (in[i])
			syndrome.rot_add (H[i / bs], (cs - i) % bs);

	//minimize counts of unsatisfied equations by flipping
	std::vector<uint> unsatisfied;
	unsatisfied.resize (cs, 0);

	for (i = 0; i < rounds; ++i) {
		uint bit, max_unsat;
		bvector tmp;
		max_unsat = 0;
		for (bit = 0; bit < cs; ++bit) {
			tmp.fill_zeros();
			tmp.rot_add (H[bit / bs], (cs - bit) % bs);
			unsatisfied[bit] = tmp.and_hamming_weight (syndrome);
			if (unsatisfied[bit] > max_unsat) max_unsat = unsatisfied[bit];
		}

		//TODO what about timing attacks?
		if (!max_unsat) break;

		uint threshold = 0;
		if (max_unsat > delta) threshold = max_unsat - delta;

		//TODO also timing (but it gets pretty statistically hard here I guess)
		uint flipped = 0;
		for (bit = 0; bit < cs; ++bit)
			if (unsatisfied[bit] > threshold) {
				in[bit] = !in[bit];
				syndrome.rot_add (H[bit / bs], (cs - bit) % bs);
				++flipped;
			}
	}

	if (i == rounds) return 2; //we simply failed

	errors = in_orig;
	errors.add (in); //get the difference
	out = in;
	out.resize (plain_size());

	return 0;
}


