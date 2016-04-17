
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

#ifndef _ccr_xsynd_h_
#define _ccr_xsynd_h_

#include "sc.h"

#include <stdint.h>

/*
 * XSYND is a stream cipher based on XSYND, the stream cipher with
 * mathematicaly provable (AND also proven) security.
 *
 * Parameters chosen for this implementation were chosen to have better attack
 * security than "standard" 2^256 and cool round numbers. Fuck speed.
 *
 * n=32768, r=1024, omega=128, b=8
 *
 * To be cool, everything is written with 64-bit integers.
 */

class xsynd : public streamcipher
{
public:
	uint64_t R1[16];

	byte block[128];
	int blockpos;

	void init();

	void clear() {
		init();
	}

	void load_key (const byte*begin, const byte*end);
	byte gen();
	void gen (size_t n, byte*out);

	//advisory values for effective usage
	size_t key_size() {
		return 128;
	}

	size_t block_size() {
		return 128;
	}
};

#endif
