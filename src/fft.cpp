
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

#include "fft.h"

#include <complex.h>
#include <fftw3.h>
#include <math.h>

/*
 * FFTW wraparound for performing fast multiplication of cyclic matrices.
 *
 * It would probably be cool to save wisdom manually or generate better plans,
 * but since we're usually doing less than 10 FFTs for each run of codecrypt,
 * the thing doesn't pay off. Feel free to implement it.
 */

#include "iohelpers.h"

void fft (bool forward, std::vector<dcx>&in, std::vector<dcx>&out)
{
	fftw_plan p;
	out.resize (in.size(), dcx (0, 0));

	p = fftw_plan_dft_1d (in.size(),
	                      //Cin, Cout,
	                      reinterpret_cast<fftw_complex*> (in.data()),
	                      reinterpret_cast<fftw_complex*> (out.data()),
	                      forward ? FFTW_FORWARD : FFTW_BACKWARD,
	                      FFTW_ESTIMATE);

	if (!forward)
		for (size_t i = 0; i < out.size(); ++i)
			out[i] /= (double) out.size();

	fftw_execute (p);
	fftw_destroy_plan (p);
}

void fft (bvector&inb, std::vector<dcx>&out)
{
	std::vector<dcx> in;
	in.resize (inb.size(), dcx (0, 0));
	for (size_t i = 0; i < inb.size(); ++i) if (inb[i]) in[i] = dcx (1, 0);
	fft (true, in, out);
}

void fft (std::vector<dcx>&in, bvector&outb)
{
	std::vector<dcx> out;
	fft (false, in, out);
	outb.resize (out.size());
	outb.fill_zeros();
	for (size_t i = 0; i < out.size(); ++i)
		if (1 & (int) round (out[i].real())) outb[i] = 1;
}
