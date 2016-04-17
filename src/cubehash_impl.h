
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

#ifndef _ccr_cubehash_impl_h_
#define _ccr_cubehash_impl_h_

#include "types.h"

#include <stdint.h>

#if __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__
#error "Only for little endian now, sorry."
#endif

#define ROT(a,b,n) (((a) << (b)) | ((a) >> (n - b)))
#define i16(cmd) for(i=0;i<16;++i) cmd;

template < int I, //initialization rounds
           int R, //rounds
           int B, //input block size, less or equal 128
           int F, //finalization rounds
           int H > //output hash size in *bytes*, not bits! less or equal 128.
class cubehash_state
{
	uint32_t X[32]; //the state

	inline void rounds (uint n) {
		int i;
		uint32_t T[16];
		for (; n; --n) {
			i16 (X[i + 16] += X[i]);
			i16 (T[i ^ 8] = X[i]);
			i16 (X[i] = ROT (T[i], 7, 32));
			i16 (X[i] ^= X[i + 16]);
			i16 (T[i ^ 2] = X[i + 16]);
			i16 (X[i + 16] = T[i]);
			i16 (X[i + 16] += X[i]);
			i16 (T[i ^ 4] = X[i]);
			i16 (X[i] = ROT (T[i], 11, 32));
			i16 (X[i] ^= X[i + 16]);
			i16 (T[i ^ 1] = X[i + 16]);
			i16 (X[i + 16] = T[i]);
		}
	}

public:
	inline void init() {
		static bool iv_init = false;
		static uint32_t IV[32];
		int i;

		if (iv_init) {
			for (i = 0; i < 32; ++i) X[i] = IV[i];
			return;
		}

		X[0] = H;
		X[1] = B;
		X[2] = R;
		for (i = 3; i < 32; ++i) X[i] = 0;
		rounds (I);

		for (i = 0; i < 32; ++i) IV[i] = X[i];
		iv_init = true;
	}

	void process_block (const byte*data) {

		int i;

		for (i = 0; i + 4 <= B; i += 4)
			X[i / 4] ^= * (uint32_t*) &data[i];

		for (; i < B; ++i)
			X[i / 4] ^= ( (uint32_t) (data[i])) << ( (i % 4) * 8);
		rounds (R);
	}

	void process_final_incomplete_block (const byte*data, int n) {

		int i;

		for (i = 0; i + 4 <= n; i += 4)
			X[i / 4] ^= * (uint32_t*) &data[i];

		for (; i < n; ++i)
			X[i / 4] ^= ( (uint32_t) (data[i])) << ( (i % 4) * 8);

		i++;
		X[i / 2] ^= ( (uint32_t) 0x80) << ( (i % 4) * 8);

		rounds (R);

		//finalize
		X[31] ^= 1;
		rounds (F);
	}

	void get_hash (byte*out) {
		for (int i = 0; i < H; ++i)
			out[i] = (X[i / 4] >> ( (i % 4) * 8)) & 0xff;
	}
};

#endif
