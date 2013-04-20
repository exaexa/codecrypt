
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

#ifndef _ccr_sha_hash_h_
#define _ccr_sha_hash_h_

#include "hash.h"
#include "sha2.h"
#include <inttypes.h>

class sha256hash : public hash_func
{
public:
	uint size() {
		return SHA256_DIGEST_LENGTH;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, (const uint8_t*) & (a[0]), a.size() );
		std::vector<byte> r;
		r.resize (size() );
		SHA256_Final ( (uint8_t*) & (r[0]), &ctx);
		return r;
	}
};

class sha512hash : public hash_func
{
public:
	uint size() {
		return SHA512_DIGEST_LENGTH;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		SHA512_CTX ctx;
		SHA512_Init (&ctx);
		SHA512_Update (&ctx, (const uint8_t*) & (a[0]), a.size() );
		std::vector<byte> r;
		r.resize (size() );
		SHA512_Final ( (uint8_t*) & (r[0]), &ctx);
		return r;
	}
};


#endif
