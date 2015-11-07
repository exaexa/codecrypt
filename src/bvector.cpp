
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

#include "bvector.h"
#include "gf2m.h"
#include "polynomial.h"

const uint64_t ones = 0xFfffFfffFfffFfffull;

void bvector::fix_padding()
{
	if (blockpos (_size))
		_data[blockof (_size)] &= ~ (ones << blockpos (_size));
}

void bvector::resize (size_t newsize, bool def)
{
	if (newsize <= _size) {
		_size = newsize;
		_data.resize (datasize (_size));
		fix_padding();
	} else {
		_data.resize (datasize (newsize), 0);
		if (def) fill_ones (_size, newsize);
		else fill_zeros (_size, newsize);
		_size = newsize;
	}
}

void bvector::fill_ones (size_t from, size_t to)
{
	for (size_t i = (from >> 6) + 1; i < (to >> 6); ++i) _data[i] = ones;
	if (blockof (from) < blockof (to)) {
		_data[blockof (from)] |= (ones << blockpos (from));
		if (blockpos (to))
			_data[blockof (to)] |=
			    (ones >> (64 - blockpos (to)));
	} else if (blockpos (to)) {
		_data[blockof (to)] |= (ones << blockpos (from))
		                       & (ones >> (64 - blockpos (to)));
	}
}

void bvector::fill_zeros (size_t from, size_t to)
{
	for (size_t i = (from >> 6) + 1; i < (to >> 6); ++i) _data[i] = 0;
	if (blockof (from) < blockof (to)) {
		_data[blockof (from)] &= ~ (ones << blockpos (from));
		if (blockpos (to))
			_data[blockof (to)] &=
			    ~ (ones >> (64 - blockpos (to)));
	} else if (blockpos (to)) {
		_data[blockof (to)] &= ~ ( (ones << blockpos (from))
		                           & (ones >> (64 - blockpos (to))));
	}
}

void bvector::append (const bvector&a)
{
	add_offset (a, _size);
}

void bvector::add_offset (const bvector&a, size_t offset_from, size_t offset_to, size_t cnt)
{
	if (!cnt) cnt = a._size; //default param

	while (cnt) {
		uint64_t mask = ones;
		if (cnt < 64) mask >>= (64 - cnt);

		if (!blockpos (offset_from)) {
			if (!blockpos (offset_to)) {
				_data[blockof (offset_to)] =
				    _data[blockof (offset_to)]
				    ^ (mask & a._data[blockof (offset_from)]);
				offset_from += 64;
				offset_to += 64;
				if (cnt < 64) return;
				cnt -= 64;
			} else {
				//offset_from is aligned, process
				_data[blockof (offset_to)]
				    = _data[blockof (offset_to)]
				      ^ ( (mask & a._data[blockof (offset_from)])
				          << blockpos (offset_to));
				size_t move = 64 - blockpos (offset_to);
				if (cnt < move) return;
				cnt -= move;
				offset_from += move;
				offset_to += move;
			}
		} else {
			if (!blockpos (offset_to)) {
				//only offset_to is aligned
				_data[blockof (offset_to)] = _data[blockof (offset_to)]
				                             ^ (mask & (a._data[blockof (offset_from)]
				                                        >> blockpos (offset_from)));
				size_t move = 64 - blockpos (offset_from);
				if (cnt < move) return;
				cnt -= move;
				offset_from += move;
				offset_to += move;
			} else {
				//nothing is aligned, realign by tiny steps
				//TODO choose whether to realign by offset_from or to
				item (offset_to) = item (offset_to) ^a.item (offset_from);
				--cnt;
				++offset_from;
				++offset_to;
			}
		}
	}
}

void bvector::add_offset (const bvector&a, size_t offset_to)
{
	if (offset_to + a._size > _size) resize (offset_to + a._size, 0);
	add_offset (a, 0, offset_to, a._size);
}

static uint uint64weight (uint64_t x)
{
	/*
	 * const-time uint64_t hamming weight, taken from wikipedia. <3
	 */

	static const uint64_t
	m1  = 0x5555555555555555,
	m2  = 0x3333333333333333,
	m4  = 0x0f0f0f0f0f0f0f0f,
	h01 = 0x0101010101010101;

	x -= (x >> 1) & m1;
	x = (x & m2) + ( (x >> 2) & m2);
	x = (x + (x >> 4)) & m4;
	return (x * h01) >> 56;
}

uint bvector::hamming_weight()
{
	uint r = 0;
	for (size_t i = 0; i < _data.size(); ++i) r += uint64weight (_data[i]);
	return r;
}

void bvector::add (const bvector&a)
{
	if (a._size > _size) resize (a._size, 0);
	add_offset (a, 0, 0, a._size);
}

void bvector::add_range (const bvector&a, size_t b, size_t e)
{
	if (e > size()) resize (e, 0);
	add_offset (a, b, b, e - b);
}

void bvector::rot_add (const bvector&a, size_t rot)
{
	size_t as = a._size;
	if (_size < as) resize (as, 0);
	rot = rot % as;
	if (!rot) add (a);
	else {
		add_offset (a, 0, rot, as - rot); //...123456
		add_offset (a, as - rot, 0, rot); //789123456
	}
}

void bvector::set_block (const bvector&a, size_t offset)
{
	if (offset + a.size() > size()) resize (offset + a.size(), 0);
	fill_zeros (offset, offset + a.size());
	add_offset (a, 0, offset, a.size());
}

void bvector::get_block (size_t offset, size_t bs, bvector&out) const
{
	if (offset + bs > size()) return;
	out.resize (bs);
	out.fill_zeros();
	out.add_offset (*this, offset, 0, bs);
}

uint bvector::and_hamming_weight (const bvector&a) const
{
	uint r = 0;
	size_t s = _data.size();
	if (s > a._data.size()) s = a._data.size();
	for (size_t i = 0; i < s; ++i) r += uint64weight (_data[i] & a._data[i]);
	return r;
}

bool bvector::zero() const
{
	//zero padding assures we don't need to care about last bits
	for (size_t i = 0; i < _data.size(); ++i) if (_data[i]) return false;
	return true;
}

void bvector::from_poly_cotrace (const polynomial&r, gf2m&fld)
{
	clear();
	size_t s = r.size();
	resize (s * fld.m, 0);
	for (size_t i = 0; i < size(); ++i)
		item (i) = (r[i % s] >> (i / s)) & 1;
}

bool bvector::to_string (std::string& out) const
{
	if (size() & 0x7) return false;

	out.clear();
	out.resize (size() >> 3, 0);

	for (size_t i = 0; i < size(); ++i)
		if (item (i)) out[i >> 3] |= (1 << (i & 0x7));

	return true;
}

void bvector::from_string (const std::string&in)
{
	clear();
	resize (in.length() << 3);

	for (size_t i = 0; i < size(); ++i)
		item (i) = (in[i >> 3] >> (i & 0x7)) & 1;
}

/*
 * utility colex (un)ranking for niederreiter and workalikes.
 * see Ruskey's Combinatorial Generation, algorithm 4.10
 *
 * Colex ranking here uses "walking" through combination number space instead
 * of caching or actual combination number generation. For a nice image, see
 * the book.
 *
 * Suppose that you have a = (n choose k)
 *
 * then:
 *   (n+1 choose k) = a * (n+1) / (n-k+1)
 *   (n-1 choose k) = a * (n-k) / n
 *   (n choose k+1) = a * (n-k) / (k+1)
 *   (n choose k-1) = a * k / (n-k+1)
 *
 * Because colex ranking forms a "path" through tne combination number space
 * (from (1 choose 1) to (length choose count)), worst operations actually use
 * at most (length+count) multiplications and divisions, for worst McEliece
 * parameters that is around 16k operations total (plus starting combination
 * number computation un case of unranking, which is around 500 long ops.)
 *
 * To compare naive approach:
 * - ranking needs computation of the same count of combination numbers as
 *   count parameter. Those are (n choose k) with average n=(length/2) and
 *   k=(count/2), every number needs 2k long operations, total operations is
 *   count*count/2 = around 32k for mceliece approach.
 * - unranking needs terrible number of "attempts" to determine each p (around
 *   13 in binary search), this basically means it uses around 0.4M long
 *   operations. Wrong way.
 *
 * For extremely sparse vectors (where 2*(length+count)>count*count/2, roughly
 * where count>2*sqrt(length)) it can be benefical to compute stuff using the
 * naive approach. This doesn't count for our McEliece parameters, so naive
 * approach is not implemented at all.
 */

#include <gmp.h>

static void combination_number (mpz_t& r, uint n, uint k)
{
	mpz_t t;
	if (k > n) {
		mpz_set_ui (r, 0);
		return;
	}

	if (k * 2 > n) k = n - k;

	mpz_set_ui (r, 1);
	mpz_init (t);

	//upper part n*(n-1)*(n-2)*...*(n-k+1)
	for (uint i = n; i > n - k; --i) {
		mpz_swap (t, r);
		mpz_mul_ui (r, t, i);
	}
	//lower part (div k!)
	for (uint i = k; i > 1; --i) {
		mpz_swap (t, r);
		mpz_tdiv_q_ui (r, t, i);
	}

	mpz_clear (t);
}

static void bvector_to_mpz (const bvector&v, mpz_t&r)
{
	mpz_set_ui (r, 0);
	mpz_realloc2 (r, v.size());
	for (uint i = 0; i < v.size(); ++i)
		if (v[i])
			mpz_setbit (r, i);
		else	mpz_clrbit (r, i);
}

static void mpz_to_bvector (mpz_t&x, bvector&r)
{
	r.resize (mpz_sizeinbase (x, 2));
	for (uint i = 0; i < r.size(); ++i)
		r[i] = mpz_tstbit (x, i);
}

void bvector::colex_rank (bvector&r) const
{
	mpz_t res, comb, t;
	mpz_init_set_ui (res, 0);
	mpz_init_set_ui (comb, 1);
	mpz_init (t);

	uint n = 0, k = 1;

	while (item (n)) ++n, ++k;  //skip the "zeroes" on the beginning

	++n; //now n=k=1, comb=1

	//non-zero positions
	for (; n < size(); ++n) {

		if (item (n)) {
			//add combination number to result
			mpz_swap (t, res);
			mpz_add (res, t, comb);
		}

		//increase n in comb
		mpz_swap (t, comb);
		mpz_mul_ui (comb, t, n + 1);
		mpz_swap (t, comb);
		mpz_fdiv_q_ui (comb, t, n - k + 1);

		if (item (n)) {
			//increase k in comb
			mpz_swap (t, comb);
			mpz_mul_ui (comb, t, n + 1 - k); //n has changed!
			mpz_swap (t, comb);
			mpz_fdiv_q_ui (comb, t, k + 1);
			++k;
		}
	}

	mpz_to_bvector (res, r);

	mpz_clear (comb);
	mpz_clear (t);
	mpz_clear (res);
}

bool bvector::colex_unrank (bvector&res, uint n, uint k) const
{
	mpz_t r, comb, t;
	mpz_init (r);
	mpz_init (comb);
	mpz_init (t);

	bvector_to_mpz (*this, r);

	combination_number (comb, n, k); //initialize to the end of path
	res.clear();

	//check if incoming r is not too big.
	if (mpz_cmp (r, comb) >= 0) {
		mpz_clear (r);
		mpz_clear (comb);
		mpz_clear (t);
		return false;
	}

	res.resize (n, 0);

	for (; k > 0; --k) {
		if (mpz_sgn (r) == 0) //zero r needs n<k -> switch to simple mode
			break;

		while (n > k && mpz_cmp (comb, r) > 0) {
			//decrease n until something <=r is found
			mpz_swap (t, comb);
			mpz_mul_ui (comb, t, n - k);
			mpz_swap (t, comb);
			mpz_fdiv_q_ui (comb, t, n);
			--n;
		}

		res[n] = 1;

		//r -= comb
		mpz_swap (t, r);
		mpz_sub (r, t, comb);

		//decrease k
		mpz_swap (t, comb);
		mpz_mul_ui (comb, t, k);
		mpz_swap (t, comb);
		mpz_fdiv_q_ui (comb, t, n - k + 1);
	}

	//do the "zeroes" rest
	for (; k > 0; --k) {
		res[k - 1] = 1;
	}

	mpz_clear (r);
	mpz_clear (comb);
	mpz_clear (t);
	return true;
}
