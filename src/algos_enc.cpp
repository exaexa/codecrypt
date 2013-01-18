
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
 *     (even if there are no message bytes in it, there still must be the zero
 *     1byte number that is telling us.)
 *   - stuff in bytes is always thought about as big-endian
 */

static void message_pad (const bvector&in, std::vector<byte>&out, prng&rng)
{
	out.clear();

	//make space for the bit stage
	if (in.size() == 0) out.resize (1, 0);
	else out.resize ( ( (in.size() - 1) >> 3) + 2, 0);

	//copy message bits
	uint i;
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
	uint overflow = out.size() & 0xff;
	uint pad_block_start = out.size() >> 8;
	uint pad_block_start_byte = pad_block_start << 8;

	//make space for the bytes
	out.resize ( (pad_block_start + 1) << 8, 0);

	//fill random bytes
	for (i = overflow; i < 0xff; ++i)
		out[i + pad_block_start_byte] = rng.random (256);

	//fill the overflow size byte
	out[pad_block_start_byte + 0xff] = overflow;
}

static bool message_unpad (const std::vector<byte>&in, bvector&out)
{
	//check byte padding sizes
	if (!in.size() ) return false;
	if (in.size() & 0xff) return false;

	//get rid of the byte padding
	uint byte_overflow = in[in.size() - 1];
	uint in_end = in.size() + byte_overflow - 256;

	//get bit padding information (now it's the last byte)
	if (!in_end) return false;
	uint bit_overflow = in[in_end - 1];

	//there must not be more than one byte of overflown bits
	if (bit_overflow >= 8) return false;

	//check if there's byte with overflow bits
	if (bit_overflow && (in_end < 2) ) return false;

	//convert to bvector
	uint msg_size = ( (in_end - (bit_overflow ? 2 : 1) ) << 3)
	                + bit_overflow;
	out.clear();
	out.resize (msg_size);
	for (uint i = 0; i < msg_size; ++i)
		out[i] = 1 & (in[i >> 3] >> (i & 0x7) );

	return true;
}

/*
 * Fujisaki-okamoto part
 */

#define min(a,b) ((a)<(b)?(a):(b))

#include "sha_hash.h"
#include "arcfour.h"

/*
 * Generic F-O functions. Note that ranksize must be equal to
 *
 * floor(log(comb(ciphersize,errorcount))/log(2))
 *
 * otherwise it probably fails. miserably.
 */

template < class pubkey_type,
         int plainsize,
         int ciphersize,
         int errorcount,
         class hash_type,
         int ranksize >
static int fo_encrypt (const bvector&plain, bvector&cipher,
                       sencode* pubkey, prng&rng)
{
	uint i;

	//load the key
	pubkey_type Pub;
	if (Pub.unserialize (pubkey) ) return 1;

	//verify that key parameters match our scheme
	if (Pub.plain_size() != plainsize) return 1;
	if (Pub.cipher_size() != ciphersize) return 1;
	if (Pub.error_count() != errorcount) return 1;

	//create the unencrypted message part
	std::vector<byte> M;
	message_pad (plain, M, rng);

	//create the symmetric key
	std::vector<byte> K;
	K.resize (plainsize >> 3);
	for (i = 0; i < K.size(); ++i) K[i] = rng.random (256);

	//create the base for error vector
	std::vector<byte> H, M2;
	M2 = M;
	M2.insert (M2.end(), K.begin(), K.end() );
	hash_type hf;
	H = hf (M2);

	//prepare the error vector
	bvector ev_rank;
	ev_rank.resize (ranksize);
	for (i = 0; i < ranksize; ++i)
		ev_rank[i] = 1 & (H[ (i >> 3) % H.size()] >> (i & 0x7) );

	bvector ev;
	ev_rank.colex_unrank (ev, ciphersize, errorcount);

	//prepare plaintext
	bvector mce_plain;
	mce_plain.resize (plainsize);
	for (i = 0; i < plainsize; ++i) mce_plain[i] = 1 & (M[i >> 3] >> (i & 0x7) );

	//run McEliece
	if (Pub.encrypt (mce_plain, cipher, ev) ) return 2;

	//encrypt the message part (xor with arcfour)
	arcfour<byte> arc;
	arc.init (8);
	//whole key must be tossed in, so split if when necessary
	for (i = 0; i < (K.size() >> 8); ++i) {
		std::vector<byte> subkey (K.begin() + (i << 8),
		                          min (K.end(),
		                               K.begin() + ( (i + 1) << 8) ) );
		arc.load_key (subkey);
	}
	arc.discard (256);
	for (i = 0; i < M.size(); ++i) M[i] = M[i] ^ arc.gen();

	//append the message part to the ciphertext
	cipher.resize (ciphersize + (M.size() << 3) );
	for (i = 0; i < (M.size() << 3); ++i)
		cipher[ciphersize + i] = 1 & (M[i >> 3] >> (i & 0x7) );

	return 0;
}

template < class privkey_type,
         int plainsize,
         int ciphersize,
         int errorcount,
         class hash_type,
         int ranksize >
static int fo_decrypt (const bvector&cipher, bvector&plain,
                       sencode* privkey)
{
	uint i;

	//load the key
	privkey_type Priv;
	if (Priv.unserialize (privkey) ) return 1;

	//verify that key parameters match the scheme
	if (Priv.plain_size() != plainsize) return 1;
	if (Priv.cipher_size() != ciphersize) return 1;
	if (Priv.error_count() != errorcount) return 1;

	//get the McE part
	if (cipher.size() < ciphersize) return 2;
	bvector mce_cipher, mce_plain, ev;
	mce_cipher.insert (mce_cipher.end(),
	                   cipher.begin(),
	                   cipher.begin() + ciphersize);

	//decrypt the symmetric key
	if (Priv.decrypt (mce_cipher, mce_plain, ev) ) return 2;

	//convert stuff to byte vectors
	std::vector<byte> K, M;
	K.resize (plainsize >> 3, 0);
	for (i = 0; i < plainsize; ++i)
		if (mce_plain[i]) K[i >> 3] |= 1 << (i & 0x7);

	uint msize = cipher.size() - ciphersize;
	if (msize & 0x7) return 2;
	M.resize (msize >> 3, 0);
	for (i = 0; i < msize; ++i)
		if (cipher[ciphersize + i]) M[i >> 3] |= 1 << (i & 0x7);

	//prepare arcfour
	arcfour<byte> arc;
	arc.init (8);
	//stuff in the whole key
	for (i = 0; i < (K.size() >> 8); ++i) {
		std::vector<byte> subkey (K.begin() + (i << 8),
		                          min (K.end(),
		                               K.begin() + ( (i + 1) << 8) ) );
		arc.load_key (subkey);
	}
	arc.discard (256);
	//decrypt the message part
	for (i = 0; i < M.size(); ++i) M[i] = M[i] ^ arc.gen();

	//compute the hash of K+M
	std::vector<byte>H, M2;
	M2 = M;
	M2.insert (M2.end(), K.begin(), K.end() );
	hash_type hf;
	H = hf (M2);

	/*
	 * prepare the error vector (again. Avoiding colex ranking which is
	 * little less deterministic than it could be (produces varying amounts
	 * of whitespace)
	 */
	bvector ev_rank, ev2;
	ev_rank.resize (ranksize);
	for (i = 0; i < ranksize; ++i)
		ev_rank[i] = 1 & (H[ (i >> 3) % H.size()] >> (i & 0x7) );
	ev_rank.colex_unrank (ev2, ciphersize, errorcount);

	//now it should match, otherwise someone mangled the message.
	if (ev != ev2) return 3;

	//if the message seems okay, unpad and return it.
	if (!message_unpad (M, plain) ) return 2;

	return 0;
}

/*
 * Instances for actual encryption/descryption algorithms
 */

int algo_mceqd128::encrypt (const bvector&plain, bvector&cipher,
                            sencode* pubkey, prng&rng)
{
	return fo_encrypt
	       < mce_qd::pubkey,
	       2048, 4096, 128,
	       sha256hash,
	       816 >
	       (plain, cipher, pubkey, rng);
}

int algo_mceqd256::encrypt (const bvector&plain, bvector&cipher,
                            sencode* pubkey, prng&rng)
{
	return fo_encrypt
	       < mce_qd::pubkey,
	       4096, 8192, 256,
	       sha512hash,
	       1638 >
	       (plain, cipher, pubkey, rng);
}

int algo_mceqd128::decrypt (const bvector&cipher, bvector&plain,
                            sencode* privkey)
{
	return fo_decrypt
	       < mce_qd::privkey,
	       2048, 4096, 128,
	       sha256hash,
	       816 >
	       (cipher, plain, privkey);
}

int algo_mceqd256::decrypt (const bvector&cipher, bvector&plain,
                            sencode* privkey)
{
	return fo_decrypt
	       < mce_qd::privkey,
	       4096, 8192, 256,
	       sha512hash,
	       1638 >
	       (cipher, plain, privkey);
}
