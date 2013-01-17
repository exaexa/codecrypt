
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

#include "algos_enc.h"

#include "mce_qd.h"

/*
 * keygen
 */

int algo_mceqd128::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	mce_qd::pubkey Pub;
	mce_qd::privkey Priv;

	if (mce_qd::generate (Pub, Priv, rng, 16, 7, 32, 4) )
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}

int algo_mceqd256::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	mce_qd::pubkey Pub;
	mce_qd::privkey Priv;

	if (mce_qd::generate (Pub, Priv, rng, 16, 8, 32, 4) )
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}

/*
 * Padding. Ha-ha.
 *
 * This wouldn't be necessary, but the ciphertext length would then very easily
 * leak information about plaintext length (= len(c) - len(McE block) ).
 * Moreover we need to somehow convert bvector bits to actual bytes.
 *
 * First, the bvector is converted to vector of bytes so it's easy to work with
 * it. Result is in the form
 *
 * bits [randombits] nrbits
 *
 * where
 *   bits = message bits
 *   randombits = randomness that pads the message bits to whole byte.
 *   nrbits = 1 byte with number of random bits applied
 *
 * Then we are padding stuff in 256-byte blocks this way:
 *
 * messagemessage [randomrandomrandom] 1bytesize
 *
 * where
 *   message = "tail" of the message that has overflown to the last block
 *   random = random bytes
 *   1bytesize = how many bytes of the mesage are there in the last block
 *
 * Note that:
 *   - the last block is _always present_
 *     (even if there's no message bytes in it.)
 *   - stuff in bytes is always thought about as big-endian
 */

static void message_pad (const bvector&in, std::vector<byte>&out, prng&rng)
{
	out.clear();

	//make space for the bit stage
	if (in.size() == 0) out.resize (1, 0);
	else out.resize ( ( (in.size() - 1) >> 3) + 2, 0);

	//copy message bits
	int i;
	for (i = 0; i < in.size(); ++i)
		if (in[i]) out[i >> 3] |= 1 << (i & 0x7);

	//pad with random bits to whole byte
	unsigned char rtmp = rng.random (256);
	for (; i & 0x7; ++i)
		if (rtmp >> (i & 0x7) )
			out[i >> 3] |= 1 << (i & 0x7);

	//append message overflow size
	out[i >> 3] = in.size() & 0x7;

	//byte stage
	int overflow = out.size() & 0xff;
	int pad_block_start = out.size() >> 8;

	//make space for the bytes
	out.resize ( (pad_block_start + 1) << 8, 0);

	//fill random bytes
	for (i = overflow; i < 0xff; ++i)
		out[i + pad_block_start] = rng.random (256);

	//fill the overflow size byte
	out[pad_block_start + 0xff] = overflow;
}

static bool message_unpad (const std::vector<byte>&in, bvector&out)
{

}

/*
 * Fujisaki-okamoto encryption scheme
 */

int algo_mceqd128::encrypt (const bvector&plain, bvector&cipher,
                            sencode* pubkey, prng&rng)
{
	return -1;
}

int algo_mceqd256::encrypt (const bvector&plain, bvector&cipher,
                            sencode* pubkey, prng&rng)
{
	return -1;
}

int algo_mceqd128::decrypt (const bvector&cipher, bvector&plain,
                            sencode* privkey)
{
	return -1;
}

int algo_mceqd256::decrypt (const bvector&cipher, bvector&plain,
                            sencode* privkey)
{
	return -1;
}
