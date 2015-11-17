
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

#include "fft.h"
#include <cmath>

using namespace mce_qcmdpc;
using namespace std;

int mce_qcmdpc::generate (pubkey&pub, privkey&priv, prng&rng,
                          uint block_size, uint block_count, uint wi,
                          uint t, uint rounds, uint delta)
{
	uint i, j;

	if (wi > block_size / 2) return 1; //safety

	priv.H.resize (block_count);
	pub.G.resize (block_count - 1);

	/*
	 * Cyclic matrices are diagonalizable by FFT so this stuff gets pretty
	 * fast. Otherwise they behave like simple polynomials over GF(2) mod
	 * (1+x^n).
	 */

	vector<dcx> H_last_inv;

	for (;;) {
		//retry generating the rightmost block until it is invertible
		bvector Hb;
		Hb.resize (block_size, 0);
		for (i = 0; i < wi; ++i)
			for (uint pos = rng.random (block_size);
			     Hb[pos] ? 1 : (Hb[pos] = 1, 0);
			     pos = rng.random (block_size));

		bvector xnm1, Hb_inv, tmp;
		xnm1.resize (block_size + 1, 0);
		xnm1[0] = 1;
		xnm1[block_size] = 1; //poly (x^n-1) in gf(2)

		/*
		 * TODO This is quadratic, speed it up.
		 *
		 * No one actually cares about keygen speed yet, but this can
		 * be done in O(n*log(n)) using Schönhage-Strassen algorithm.
		 * If speed is required (e.g. for SPF in some ssl replacement,
		 * *wink* *wink*), use libNTL's GF2X.
		 *
		 * NTL one uses simpler Karatsuba with ~O(n^1.58) which should
		 * (according to wikipedia) be faster for sizes under 32k bits
		 * because of constant factors involved.
		 */
		bvector rem = Hb.ext_gcd (xnm1, Hb_inv, tmp);
		if (!rem.one()) continue; //not invertible, retry
		if (Hb_inv.size() > block_size) continue; //totally weird.
		Hb_inv.resize (block_size, 0); //pad polynomial with zeros

		//if it is, save it to matrix
		priv.H[block_count - 1] = Hb;

		//precompute the fft of the inverted last block
		fft (Hb_inv, H_last_inv);

		break; //success
	}

	//generate the rests of matrix blocks, fill the G right away.
	for (i = 0; i < block_count - 1; ++i) {
		bvector Hb;
		Hb.resize (block_size, 0);

		//generate the polynomial corresponding to the first row
		for (j = 0; j < wi; ++j)
			for (uint pos = rng.random (block_size);
			     Hb[pos] ? 1 : (Hb[pos] = 1, 0);
			     pos = rng.random (block_size));

		//save it to H
		priv.H[i] = Hb;

		//compute inv(H[last])*H[i]
		vector<dcx> H;
		fft (Hb, H);
		for (j = 0; j < block_size; ++j)
			H[j] *= H_last_inv[j];
		fft (H, Hb);

		//save it to G
		pub.G[i] = Hb;
		pub.G[i].resize (block_size, 0);
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
	uint blocks = G.size();
	for (uint i = 1; i < blocks; ++i)
		if (G[i].size() != bs) return 1; //prevent mangled keys

	//first, the checksum part
	vector<dcx> bcheck, Pd, Gd;
	bcheck.resize (bs, dcx (0, 0)); //initially zero
	bvector block;

	/*
	 * G stores first row(s) of the circulant matrix blocks.  Proceed block
	 * by block and construct the checksum.
	 *
	 * On a side note, it would be cool to store the G already pre-FFT'd,
	 * but the performance gain wouldn't be interesting enough to
	 * compensate for 128 times larger public key (each bit would get
	 * expanded to two doubles). Do it if you want to encrypt bulk data.
	 */

	for (size_t i = 0; i < blocks; ++i) {
		in.get_block (i * bs, bs, block);
		fft (block, Pd);
		fft (G[i], Gd);
		for (size_t j = 0; j < bs; ++j)
			bcheck[j] += Pd[j] * Gd[j];
	}

	//compute the ciphertext
	out = in;
	fft (bcheck, block); //get the checksum part
	out.append (block);
	out.add (errors);

	return 0;
}

int privkey::decrypt (const bvector & in, bvector & out)
{
	bvector tmp_errors;
	return decrypt (in, out, tmp_errors);
}

#include <vector>
#include <list>

int privkey::decrypt (const bvector & in_orig, bvector & out, bvector & errors)
{
	uint i, j;
	uint cs = cipher_size();

	if (in_orig.size() != cs) return 1;
	uint bs = H[0].size();
	uint blocks = H.size();
	for (i = 1; i < blocks; ++i) if (H[i].size() != bs) return 2;

	bvector in = in_orig; //we will modify this.

	/*
	 * probabilistic decoding!
	 */

	vector<dcx> synd_diag, tmp, Htmp;
	synd_diag.resize (bs, dcx (0, 0));

	//precompute the syndrome
	for (i = 0; i < blocks; ++i) {
		bvector b;
		b.resize (bs, 0);
		b.add_offset (in, bs * i, 0, bs);
		fft (b, tmp);
		fft (H[i], Htmp);
		for (j = 0; j < bs; ++j) synd_diag[j] += Htmp[j] * tmp[j];
	}

	bvector (syndrome);
	fft (synd_diag, syndrome);

	//precompute sparse matrix indexes
	vector<list<uint> > Hsp;
	Hsp.resize (blocks);
	for (i = 0; i < blocks; ++i)
		for (j = 0; j < bs; ++j)
			if (H[i][j])
				Hsp[i].push_back (j);

	/*
	 * count the correlations, abuse the sparsity of matrices.
	 *
	 * TODO updating the counts and so is the slowest part of the whole
	 * thing. It's all probabilistic, maybe there could be some potential
	 * to speed it up by discarding some (already missing) precision.
	 *
	 * FFT would be a cool candidate.
	 */

	vector<unsigned> unsat;
	unsat.resize (cs, 0);

	for (uint blk = 0; blk < blocks; ++blk)
		for (uint i : Hsp[blk]) {
			for (j = 0; j < bs; ++j)
				if (syndrome[j])
					++unsat[blk * bs + (j + bs - i) % bs];
		}

	uint round;
	for (round = 0; round < rounds; ++round) {

		uint max_unsat = 0;
		for (i = 0; i < cs; ++i)
			if (unsat[i] > max_unsat) max_unsat = unsat[i];
		if (!max_unsat) break;
		if (max_unsat > bs) return 3;
		//TODO do something about possible timing attacks

		uint threshold = 0;
		if (max_unsat > delta) threshold = max_unsat - delta;

		for (uint bit = 0; bit < cs; ++bit) {
			if (unsat[bit] <= threshold) continue;

			/*
			 * heavy trickery starts here, we carefully
			 * modify the state to avoid necessity of
			 * recomputation as a whole.
			 */

			uint blk = bit / bs, blkpos = bit % bs;

			//adjust the error counts that were
			//caused by this column of H
			for (uint hpos : Hsp[blk]) {
				hpos += blkpos;
				//decide whether there's 1 or 0
				bool increase = !syndrome[hpos % bs];
				for (uint b2 = 0; b2 < blocks; ++b2)
					for (uint h2 : Hsp[b2]) {
						unsigned&
						ref = unsat
						      [b2 * bs
						       + (hpos + bs - h2) % bs];
						if (increase) ++ref;
						else --ref;
					}

				//and flip it
				syndrome.flip (hpos % bs);
			}

			//fix the bit
			in.flip (bit);
		}
	}

	if (round == rounds) return 4; //we simply failed, haha.

	errors = in_orig;
	errors.add (in); //get the difference
	out = in;
	out.resize (plain_size());

	return 0;
}


