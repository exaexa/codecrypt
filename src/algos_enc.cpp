
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

template<int m, int T, int b, int d>
static int mceqd_create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	mce_qd::pubkey Pub;
	mce_qd::privkey Priv;

	if (mce_qd::generate (Pub, Priv, rng, m, T, b, d))
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
 * Then we are padding stuff with a padding of length at most 255 blocks, from
 * both sides:
 *
 * 1bytesize [randomrandom] messagemessage [randomrandomrandom] 1bytesize
 *
 * where
 *   message = "tail" of the message that has overflown to the last block
 *   random = random bytes
 *   1bytesize = how many bytes do corresponding random data have.
 *
 * Note that:
 *   - the last block is _always present_
 *     (even if there are no message bytes in it, there still must be the zero
 *     1byte number that is telling us.)
 *   - stuff in bytes is always thought about as big-endian
 *
 * 1bytesize is determined from message and message length in bits, as:
 *
 * size_start = h1(msg) + h2(|msg|)
 * size_start = h3(msg) + h4(|msg|)
 *
 * where h1 to h4 are hash functions to [0..127]
 */

#include <stdint.h>
#include "hash.h"

static void msg_pad_length (const std::vector<byte>& msg,
                            byte&start, byte&end,
                            hash_func&pad_hash)
{
	uint64_t len = msg.size();
	std::vector<byte> lenbytes;
	lenbytes.resize (sizeof (uint64_t), 0);
	for (uint i = 0; i < sizeof (uint64_t); ++i) {
		lenbytes[i] = len & 0xff;
		len >>= 8;
	}

	std::vector<byte> tmp;

	tmp = pad_hash (lenbytes);
	start = tmp[0] & 0x7f;
	end = tmp[1] & 0x7f;
	tmp = pad_hash (msg);
	start += tmp[0] & 0x7f;
	end += tmp[1] & 0x7f;
}

static void message_pad (const bvector&in, std::vector<byte>&out,
                         prng&rng, hash_func&pad_hash)
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
		if (rtmp >> (i & 0x7))
			out[i >> 3] |= 1 << (i & 0x7);

	//append message overflow size
	out[i >> 3] = in.size() & 0x7;

	//byte stage
	byte padsize_begin, padsize_end;
	msg_pad_length (out, padsize_begin, padsize_end, pad_hash);

	//padding at the beginning
	out.insert (out.begin(), 1 + (uint) padsize_begin, 0);
	out[0] = padsize_begin;
	for (i = 1; i <= padsize_begin; ++i)
		out[i] = rng.random (256);

	//tail padding
	uint out_end = out.size();
	out.resize (out_end + padsize_end + 1, 0);
	for (i = 0; i < padsize_end; ++i)
		out[out_end + i] = rng.random (256);
	out[out_end + padsize_end] = padsize_end;
}

static bool message_unpad (std::vector<byte> in, bvector&out,
                           hash_func&pad_hash)
{
	//check byte padding sizes
	if (!in.size()) return false;

	//get rid of the byte padding
	uint padsize_begin, padsize_end;

	padsize_begin = in[0];
	padsize_end = in[in.size() - 1];
	//check if it really fits
	//(2 bytes padding + 1 byte min padded msg length)
	if ( (uint) padsize_begin + (uint) padsize_end + 3 > in.size())
		return false;

	//get rid of beginning padding
	in.erase (in.begin(), in.begin() + 1 + (uint) padsize_begin);

	uint in_end = in.size() - padsize_end - 1;
	in.resize (in_end);

	/* check if padding was really okay. Note that it is not necessary
	 * since the padded message is "already checked" for mangling by F-O
	 * padding. This is only a check that sender uses the same valid
	 * padding method as we do. */
	byte check_begin, check_end;
	msg_pad_length (in, check_begin, check_end, pad_hash);
	if (padsize_begin != check_begin || padsize_end != check_end)
		return false;

	//get bit padding information (now it's the last byte)
	uint bit_overflow = in[in_end - 1];

	//there must not be more than one byte of overflown bits
	if (bit_overflow >= 8) return false;

	//check if there's byte with overflow bits
	if (bit_overflow && (in_end < 2)) return false;

	//convert to bvector
	uint msg_size = ( (in_end - (bit_overflow ? 2 : 1)) << 3)
	                + bit_overflow;
	out.clear();
	out.resize (msg_size);
	for (uint i = 0; i < msg_size; ++i)
		out[i] = 1 & (in[i >> 3] >> (i & 0x7));

	return true;
}

/*
 * Fujisaki-okamoto part
 */

#define MIN(a,b) ((a)<(b)?(a):(b))

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
           class pad_hash_type,
           class scipher,
           int ranksize >
static int fo_encrypt (const bvector&plain, bvector&cipher,
                       sencode* pubkey, prng&rng)
{
	uint i;

	//load the key
	pubkey_type Pub;
	if (!Pub.unserialize (pubkey)) return 1;

	//verify that key parameters match our scheme
	if (Pub.plain_size() != plainsize) return 2;
	if (Pub.cipher_size() != ciphersize) return 3;
	if (Pub.error_count() != errorcount) return 4;

	//create the unencrypted message part
	std::vector<byte> M;
	pad_hash_type phf;
	message_pad (plain, M, rng, phf);

	//create the symmetric key
	std::vector<byte> K;
	K.resize (plainsize >> 3);
	for (i = 0; i < K.size(); ++i) K[i] = rng.random (256);

	//create the base for error vector
	std::vector<byte> H, M2;
	M2 = M;
	M2.insert (M2.end(), K.begin(), K.end());
	hash_type hf;
	H = hf (M2);

	//prepare the error vector
	bvector ev_rank;
	ev_rank.resize (ranksize);
	for (i = 0; i < ranksize; ++i)
		ev_rank[i] = 1 & (H[ (i >> 3) % H.size()] >> (i & 0x7));

	bvector ev;
	ev_rank.colex_unrank (ev, ciphersize, errorcount);

	//prepare plaintext
	bvector mce_plain;
	mce_plain.resize (plainsize);
	for (i = 0; i < plainsize; ++i) mce_plain[i] = 1 & (K[i >> 3] >> (i & 0x7));

	//run McEliece
	if (Pub.encrypt (mce_plain, cipher, ev)) return 5;

	//encrypt the message part
	scipher sc;
	sc.init ();
	//whole key must be tossed in, so split if when necessary
	sc.load_key_vector (K);

	//encrypt
	for (i = 0; i < M.size(); ++i) M[i] = M[i] ^ sc.gen();

	//append the message part to the ciphertext
	cipher.resize (ciphersize + (M.size() << 3));
	for (i = 0; i < (M.size() << 3); ++i)
		cipher[ciphersize + i] = 1 & (M[i >> 3] >> (i & 0x7));

	return 0;
}

template < class privkey_type,
           int plainsize,
           int ciphersize,
           int errorcount,
           class hash_type,
           class pad_hash_type,
           class scipher,
           int ranksize >
static int fo_decrypt (const bvector&cipher, bvector&plain,
                       sencode* privkey)
{
	uint i;

	//load the key
	privkey_type Priv;
	if (!Priv.unserialize (privkey)) return 1;

	if (Priv.prepare()) return 100;

	//verify that key parameters match the scheme
	if (Priv.plain_size() != plainsize) return 2;
	if (Priv.cipher_size() != ciphersize) return 3;
	if (Priv.error_count() != errorcount) return 4;

	//get the McE part
	if (cipher.size() < ciphersize) return 5;
	bvector mce_cipher, mce_plain, ev;
	mce_cipher.insert (mce_cipher.end(),
	                   cipher.begin(),
	                   cipher.begin() + ciphersize);

	//get and check the message size for later
	uint msize = cipher.size() - ciphersize;
	if (msize & 0x7) return 6;

	/*
	 * There is an (easy) timing attack on McEliece variants' decryption
	 * that determines whether McEliece decoding failed or CCA2 padding
	 * verification failed and can be (pretty easily) used to recover all
	 * errors in the error vector. To make it a (whole lot) harder, we make
	 * sure that following computation runs the same in both cases, at
	 * least to practical extent.
	 *
	 * Note that this doesn't cover potential attack on underlying
	 * rootfinding algorithm (but that one is way harder to run correctly).
	 *
	 * bool failed is volatile because we need to force the compiler not to
	 * optimize out the loop that constructs the dummy error vector.
	 */

	//decrypt the symmetric key
	volatile bool failed = Priv.decrypt (mce_cipher, mce_plain, ev);

	/*
	 * if decoding failed, ev contains something weird. We need to make it
	 * to contain some dummy (but still valid) error vector that would work
	 * with CCA2 verification and fail later.
	 *
	 * ev now contains the broken error vector; let's fix it up to
	 *
	 * 11111(errorcount of 1s)111100000000000
	 */

	for (i = 0; i < ev.size(); ++i)
		ev[i] = failed ? (i < errorcount) : ev[i];

	//convert stuff to byte vectors
	std::vector<byte> K, M;
	K.resize (plainsize >> 3, 0);
	for (i = 0; i < plainsize; ++i)
		if (mce_plain[i]) K[i >> 3] |= 1 << (i & 0x7);

	M.resize (msize >> 3, 0);
	for (i = 0; i < msize; ++i)
		if (cipher[ciphersize + i]) M[i >> 3] |= 1 << (i & 0x7);

	//prepare symmetric cipher
	scipher sc;
	sc.init ();
	//stuff in the whole key
	sc.load_key_vector (K);

	//decrypt the message part
	for (i = 0; i < M.size(); ++i) M[i] = M[i] ^ sc.gen();

	//compute the hash of K+M
	std::vector<byte>H, M2;
	M2 = M;
	M2.insert (M2.end(), K.begin(), K.end());
	hash_type hf;
	H = hf (M2);

	//colex rank the vector to hash (it is faster than unranking)
	bvector ev_rank;
	ev.colex_rank (ev_rank);
	ev_rank.resize (ranksize, 0);
	for (i = 0; i < ranksize; ++i)
		if (ev_rank[i] != (1 & (H[ (i >> 3) % H.size()]
		                        >> (i & 0x7))))
			return 7;


	//if the message seems okay, unpad and return it.
	pad_hash_type phf;
	if (!message_unpad (M, plain, phf)) return 8;

	return 0;
}

/*
 * Instances for actual keygen/encryption/descryption algorithms
 */

#define mceqd_create_keypair_func(name,m,T,b,d) \
int algo_mceqd##name::create_keypair (sencode**pub, sencode**priv, prng&rng) \
{ \
	return mceqd_create_keypair<m, T, b, d> (pub, priv, rng); \
}

#if HAVE_CRYPTOPP==1

mceqd_create_keypair_func (128, 16, 7, 32, 4)
mceqd_create_keypair_func (192, 16, 8, 27, 4)
mceqd_create_keypair_func (256, 16, 8, 32, 4)
mceqd_create_keypair_func (128cha, 16, 7, 32, 4)
mceqd_create_keypair_func (192cha, 16, 8, 27, 4)
mceqd_create_keypair_func (256cha, 16, 8, 32, 4)
mceqd_create_keypair_func (128xs, 16, 7, 32, 4)
mceqd_create_keypair_func (192xs, 16, 8, 27, 4)
mceqd_create_keypair_func (256xs, 16, 8, 32, 4)

#endif //HAVE_CRYPTOPP==1

mceqd_create_keypair_func (128cube, 16, 7, 32, 4)
mceqd_create_keypair_func (192cube, 16, 8, 27, 4)
mceqd_create_keypair_func (256cube, 16, 8, 32, 4)
mceqd_create_keypair_func (128cubecha, 16, 7, 32, 4)
mceqd_create_keypair_func (192cubecha, 16, 8, 27, 4)
mceqd_create_keypair_func (256cubecha, 16, 8, 32, 4)
mceqd_create_keypair_func (128cubexs, 16, 7, 32, 4)
mceqd_create_keypair_func (192cubexs, 16, 8, 27, 4)
mceqd_create_keypair_func (256cubexs, 16, 8, 32, 4)

#include "arcfour.h"
#include "chacha.h"
#include "xsynd.h"

typedef arcfour<byte, 8, 4096> arcfour_fo_cipher;

#define mceqd_create_encdec_func(name,plainsize,ciphersize,errcount, hash_type,pad_hash_type,scipher,ranksize) \
int algo_mceqd##name::encrypt (const bvector&plain, bvector&cipher, \
                               sencode* pubkey, prng&rng) \
{ \
	return fo_encrypt \
	       < mce_qd::pubkey, \
	       plainsize, ciphersize, errcount, \
	       hash_type, \
	       pad_hash_type, \
	       scipher, \
	       ranksize > \
	       (plain, cipher, pubkey, rng); \
} \
int algo_mceqd##name::decrypt (const bvector&cipher, bvector&plain, \
                               sencode* privkey) \
{ \
	return fo_decrypt \
	       < mce_qd::privkey, \
	       plainsize, ciphersize, errcount, \
	       hash_type, \
	       pad_hash_type, \
	       scipher, \
	       ranksize > \
	       (cipher, plain, privkey); \
}


#if HAVE_CRYPTOPP==1

#include "sha_hash.h"
#include "rmd_hash.h"

mceqd_create_encdec_func (128, 2048, 4096, 128, sha256hash, rmd128hash, arcfour_fo_cipher, 816)
mceqd_create_encdec_func (192, 2816, 6912, 256, sha384hash, rmd128hash, arcfour_fo_cipher, 1574)
mceqd_create_encdec_func (256, 4096, 8192, 256, sha512hash, rmd128hash, arcfour_fo_cipher, 1638)
mceqd_create_encdec_func (128cha, 2048, 4096, 128, sha256hash, rmd128hash, chacha20, 816)
mceqd_create_encdec_func (192cha, 2816, 6912, 256, sha384hash, rmd128hash, chacha20, 1574)
mceqd_create_encdec_func (256cha, 4096, 8192, 256, sha512hash, rmd128hash, chacha20, 1638)
mceqd_create_encdec_func (128xs, 2048, 4096, 128, sha256hash, rmd128hash, xsynd, 816)
mceqd_create_encdec_func (192xs, 2816, 6912, 256, sha384hash, rmd128hash, xsynd, 1574)
mceqd_create_encdec_func (256xs, 4096, 8192, 256, sha512hash, rmd128hash, xsynd, 1638)

#endif //HAVE_CRYPTOPP==1

#include "cube_hash.h"

mceqd_create_encdec_func (128cube, 2048, 4096, 128, cube256hash, cube128hash, arcfour_fo_cipher, 816)
mceqd_create_encdec_func (192cube, 2816, 6912, 256, cube384hash, cube128hash, arcfour_fo_cipher, 1574)
mceqd_create_encdec_func (256cube, 4096, 8192, 256, cube512hash, cube128hash, arcfour_fo_cipher, 1638)
mceqd_create_encdec_func (128cubecha, 2048, 4096, 128, cube256hash, cube128hash, chacha20, 816)
mceqd_create_encdec_func (192cubecha, 2816, 6912, 256, cube384hash, cube128hash, chacha20, 1574)
mceqd_create_encdec_func (256cubecha, 4096, 8192, 256, cube512hash, cube128hash, chacha20, 1638)
mceqd_create_encdec_func (128cubexs, 2048, 4096, 128, cube256hash, cube128hash, xsynd, 816)
mceqd_create_encdec_func (192cubexs, 2816, 6912, 256, cube384hash, cube128hash, xsynd, 1574)
mceqd_create_encdec_func (256cubexs, 4096, 8192, 256, cube512hash, cube128hash, xsynd, 1638)
