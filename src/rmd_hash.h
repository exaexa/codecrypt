

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

#ifndef _sha_hash_h_
#define _sha_hash_h_

#include "hash.h"
#include "ripemd128.h"

class rmd128hash : public hash_func
{
public:
	uint size() {
		return RIPEMD128_DIGEST_LENGTH;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		ampheck_ripemd128 ctx;
		ampheck_ripemd128_init (&ctx);
		ampheck_ripemd128_update (&ctx, (const uint8_t*) & (a[0]), a.size() );
		std::vector<byte> r;
		r.resize (size() );
		ampheck_ripemd128_finish (&ctx, (uint8_t*) & (r[0]) );
		return r;
	}
};

#endif
