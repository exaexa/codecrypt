
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

#include "algo_suite.h"

#include "algos_enc.h"
#include "algos_sig.h"

void fill_algorithm_suite (algorithm_suite&s)
{

	static algo_mceqd128 mce128;
	mce128.register_into_suite (s);

	static algo_mceqd256 mce256;
	mce256.register_into_suite (s);

	static algo_fmtseq128 fmt128;
	fmt128.register_into_suite (s);

	static algo_fmtseq192 fmt192;
	fmt192.register_into_suite (s);

	static algo_fmtseq256 fmt256;
	fmt256.register_into_suite (s);
}
