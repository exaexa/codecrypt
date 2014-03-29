
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

#ifndef _ccr_chacha_h_
#define _ccr_chacha_h_

#include "types.h"
#include "sc.h"

#include <sys/types.h>
#include <stdint.h>

class chacha20 : public streamcipher
{
	/*
	 * This implementation uses Nonce as actual part of the key, as we do
	 * not have any actual use for nonce-ing here. From that reason, keys
	 * are 40byte (320bit). We always use the "32byte" expansion.
	 */

	uint32_t key[10];
	uint32_t counter[2];

	byte block[64];
	int blockpos; //64 = no block data allocated

	void init();

	void clear() {
		init();
	}

	void load_key (const byte*begin, const byte*end);
	byte gen();
	void gen (size_t n, byte*out);

	size_t key_size() {
		return 32 + 8;
	}

	size_t block_size() {
		return 64;
	}
};

#endif
