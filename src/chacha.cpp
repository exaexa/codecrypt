
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

#include "chacha.h"

void chacha_gen (const uint32_t*key, const uint32_t*counter, uint32_t*out)
{
	uint32_t j[16], x[16];
	int i;
	static const char sigma[] = "expand 32-byte k";

	//key setup
	for (i = 0; i < 4; ++i)
		j[i] = ( (uint32_t*) sigma) [i]; //constants

	for (i = 0; i < 8; ++i)
		j[4 + i] = key[i]; //key material

	for (i = 0; i < 2; ++i)
		j[14 + i] = key[8 + i]; //part of key also counts as nonce

	for (i = 0; i < 2; ++i)
		j[12 + i] = counter[i]; //counter

	//rounds&mixing
	for (i = 0; i < 16; ++i) x[i] = j[i];

#define rotl32(val,n) \
	(((uint32_t)((val)<<(n)))|((val)>>(32-(n))))

#define qtrround(a,b,c,d) \
	x[a]=x[a]+x[b]; x[d]=rotl32(x[d]^x[a], 16); \
	x[c]=x[c]+x[d]; x[b]=rotl32(x[b]^x[c], 12); \
	x[a]=x[a]+x[b]; x[d]=rotl32(x[d]^x[a], 8); \
	x[c]=x[c]+x[d]; x[b]=rotl32(x[b]^x[c], 7);

	for (i = 0; i < 10 /* lol quarterjoke */; ++i) {
		qtrround (0, 4, 8, 12);
		qtrround (1, 5, 9, 13);
		qtrround (2, 6, 10, 14);
		qtrround (3, 7, 11, 15);
		qtrround (0, 5, 10, 15);
		qtrround (1, 6, 11, 12);
		qtrround (2, 7, 8, 13);
		qtrround (3, 4, 9, 14);
	}

	//output the round
	for (i = 0; i < 16; ++i) out[i] = x[i] + j[i];
}

void chacha_incr_counter (uint32_t*counter)
{
	counter[0]++;
	if (!counter[0]) counter[1]++;
}

void chacha20::init()
{
	for (int i = 0; i < 10; ++i) key[i] = 0;
	for (int i = 0; i < 2; ++i) counter[i] = 0;

	blockpos = 256;
}

void chacha20::load_key (const byte*begin, const byte*end)
{
	if (begin >= end) return; //invalid usage

	byte *ckey = (byte*) key;
	byte *kp = ckey;
	const byte *b = begin;

	for (; b < end; ++b) { //stuff in whole key
		*kp = *b ^ *kp;
		if (++kp > ckey + 40) kp = ckey;
	}

	b = begin;
	for (; kp < ckey + 40; ++kp) { //fill up the rest
		*kp = *b ^*kp;
		if (++b == end) b = begin;
	}
}

byte chacha20::gen()
{
	byte r;
	gen (1, &r);
	return r;
}

void chacha20::gen (size_t n, byte*out)
{
	//empty the block buffer first
	while (n && blockpos < 64) {
		if (out) * (out++) = block[blockpos++];
		else blockpos++;
		--n;
	}

	//fill in whole blocks
	while (n >= 64) {
		if (out) chacha_gen (key, counter, (uint32_t*) &out);

		chacha_incr_counter (counter);
		out += 64;
		n -= 64;
	}

	if (!n) return;

	//generate the last truncated block
	blockpos = 0;
	chacha_gen (key, counter, (uint32_t*) block);
	chacha_incr_counter (counter);

	while (n) {
		if (out) * (out++) = block[blockpos++];
		else blockpos++;
		--n;
	}
}
