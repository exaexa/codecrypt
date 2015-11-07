
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

#include "matrix.h"
#include "prng.h"
#include "permutation.h"

void matrix::resize2 (uint w, uint h, bool def)
{
	resize (w);
	for (uint i = 0; i < w; ++i) item (i).resize (h, def);
}

void matrix::zero ()
{
	uint w = width(), h = height();
	for (uint i = 0; i < w; ++i)
		for (uint j = 0; j < h; ++j)
			item (i, j) = 0;
}

void matrix::unit (uint size)
{
	clear();
	resize (size);
	for (uint i = 0; i < size; ++i) {
		item (i).resize (size, 0);
		item (i) [i] = 1;
	}
}

matrix matrix::operator* (const matrix&a)
{
	matrix r = *this;
	r.mult (a);
	return r;
}

void matrix::compute_transpose (matrix&r)
{
	uint h = height(), w = width(), i, j;
	r.resize (h);
	for (i = 0; i < h; ++i) {
		r[i].resize (w);
		for (j = 0; j < w; ++j) r[i][j] = item (j) [i];
	}
}

void matrix::mult (const matrix&right)
{
	//trivial multiply
	matrix leftT;
	compute_transpose (leftT);
	uint w = right.width(), h = leftT.width(), i, j;
	resize (w);
	for (i = 0; i < w; ++i) {
		item (i).resize (h);
		for (j = 0; j < h; ++j) item (i) [j] = leftT[j] * right[i];
	}
}

bool matrix::compute_inversion (matrix&res, bool upper_tri, bool lower_tri)
{
	//gauss-jordan elimination with inversion of the second matrix.
	//we are computing with transposed matrices for simpler row ops

	uint s = width();
	if (s != height()) return false;
	matrix m, r;
	r.unit (s);
	this->compute_transpose (m);

	uint i, j;

	//gauss step, create a lower triangular out of m, mirror to r
	if (!upper_tri) for (i = 0; i < s; ++i) {
			//we need pivoting 1 at [i][i]. If there's none, get it below.
			if (m[i][i] != 1) {
				for (j = i + 1; j < s; ++j) if (m[j][i] == 1) break;
				if (j == s) return false; //noninvertible
				m[i].swap (m[j]);
				r[i].swap (r[j]);
			}
			//remove 1's below
			if (lower_tri) {
				for (j = i + 1; j < s; ++j) if (m[j][i]) {
						m[j].add_range (m[i], 0, j + 1);
						r[j].add_range (r[i], 0, j + 1);
					}
			} else {
				for (j = i + 1; j < s; ++j) if (m[j][i]) {
						m[j].add (m[i]);
						r[j].add (r[i]);
					}
			}
		}

	//jordan step
	if (!lower_tri) {
		if (upper_tri) {
			for (i = s; i > 0; --i)
				for (j = i - 1; j > 0; --j)
					if (m[j - 1][i - 1])
						r[j - 1].add_range (r[i - 1], i - 1, s);
		} else {
			for (i = s; i > 0; --i)
				for (j = i - 1; j > 0; --j)
					if (m[j - 1][i - 1])
						r[j - 1].add (r[i - 1]);
		}
	}

	r.compute_transpose (res);
	return true;
}

bool matrix::get_right_square (matrix&r)
{
	uint h = height(), w = width();
	if (w < h) return false;
	r.clear();
	r.resize (h);
	for (uint i = 0; i < h; ++i) r[i] = item (w - h + i);
	return true;
}

bool matrix::strip_right_square (matrix&r)
{
	uint h = height(), w = width();
	if (w < h) return false;
	r.clear();
	r.resize (w - h);
	for (uint i = 0; i < w - h; ++i) r[i] = item (i);
	return true;
}

void matrix::extend_left_compact (matrix&r)
{
	uint i;
	uint h = height(), w = width();
	r.clear();
	r.resize (h + w);
	for (i = 0; i < h; ++i) {
		r[i].resize (h, 0);
		r[i][i] = 1;
	}
	for (i = 0; i < w; ++i) {
		r[h + i] = item (i);
	}
}

bool matrix::create_goppa_generator (matrix&g, permutation&p, prng&rng)
{
	p.generate_random (width(), rng);
	return create_goppa_generator (g, p);
}

bool matrix::create_goppa_generator (matrix&g, const permutation&p)
{
	matrix t, sinv, s;

	//generator construction from Barreto's PQC-4 slides p.21
	p.permute (*this, t);
	t.get_right_square (sinv);
	if (!sinv.compute_inversion (s)) return false;  //meant to be retried.

	//TODO why multiply and THEN strip?
	s.mult (t);
	s.strip_right_square (t); //matrix pingpong for the result
	t.compute_transpose (s);
	s.extend_left_compact (g);
	return true;
}

bool matrix::set_block (uint x, uint y, const matrix&b)
{
	uint h = b.height(), w = b.width();
	if (width() < x + w) return false;
	if (height() < y + h) return false;
	for (uint i = 0; i < w; ++i)
		for (uint j = 0; j < h; ++j) item (x + i, y + j) = b.item (i, j);
	return true;
}
