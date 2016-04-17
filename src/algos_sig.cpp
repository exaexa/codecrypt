
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

#include "algos_sig.h"

#include "fmtseq.h"
#include "hash.h"
#include "chacha.h"

/*
 * DISCUSSION.
 *
 * Because the Merkle signatures "trapdoor" function isn't really trapdoor but
 * plain uninvertible, every message in the scheme MUST have exactly one
 * possible signature -- well there's no possibility to verify stuff
 * nondeterministically. That completely sucks, because we can't get any
 * coolness of "Probabilistic signature scheme" as known from RSA and others
 * with inversion possibilities.
 *
 * That basically means that plaintexts MUST be prepared in the way that the
 * signer knows they will never collide with anything he could want to sign (or
 * especially NOT want to sign). Hopefully this is a common practice for
 * digital signatures now.
 *
 * This scheme, apart from actual signature, protects against finding a
 * low-length hash collision (which isn't very hard, assuming general
 * availability of amounts of storage suitable for rainbow tables) by expanding
 * the message to a reasonable minimum length prior to hashing. Algorithm is
 * simple:
 *
 * 1. convert message from bvector to byte representation
 *
 * 2. if message is longer than the minimum length, forget padding :)
 *
 * 3. if it's shorter, use it as a seed for PRNG and pad it with PRNG output to
 *    minimum length.
 *
 * Then hash it as usual, FMTSeq it, publish the signature, enjoy.
 */

#define MIN(a,b) ((a)<(b)?(a):(b))

typedef chacha20 padding_generator;

static void msg_pad (const bvector&in, std::vector<byte>&out, size_t tgt_size)
{
	uint i;

	in.to_bytes (out);
	if (out.size() >= tgt_size) return;

	padding_generator g;
	g.init ();
	//stuff in as much seed material as possible
	g.load_key_vector (out);

	i = out.size();
	out.resize (tgt_size);
	for (; i < tgt_size; ++i) out[i] = g.gen();
}

/*
 * actual signature stuff.
 */

template < int h, int l, int hs,
           class message_hash, class tree_hash, class generator >
static int fmtseq_generic_sign (const bvector&msg,
                                bvector&sig,
                                sencode**privkey,
                                bool&dirty,
                                prng&rng)
{
	//load the key
	fmtseq::privkey Priv;
	if (!Priv.unserialize (*privkey)) return 1;

	//check parameters
	if ( (Priv.h != h) || (Priv.l != l)
	     || (Priv.hs != hs)) return 2;

	//prepare the message and hash it
	std::vector<byte> M, H;
	msg_pad (msg, M, hs);
	message_hash msghf;
	H = msghf (M);

	//convert to bvector
	bvector hash;
	hash.from_bytes (H);

	//make a signature
	tree_hash hf;
	generator g;
	if (Priv.sign (hash, sig, hf, g)) return 3;

	//if it went okay, refresh the privkey
	sencode* new_pk = Priv.serialize();
	if (!new_pk) return 4;
	sencode_destroy (*privkey);
	*privkey = new_pk;
	dirty = true;

	//all OK.
	return 0;
}

template <int h, int l, int hs, class message_hash, class tree_hash>
static int fmtseq_generic_verify (const bvector&sig,
                                  const bvector&msg,
                                  sencode*pubkey)
{
	//load the key
	fmtseq::pubkey Pub;
	if (!Pub.unserialize (pubkey)) return 1;

	//check parameters
	if ( (Pub.H != h * l) || (Pub.hs != hs)) return 2;

	//prepare the message and hash it
	std::vector<byte> M, H;
	msg_pad (msg, M, hs);
	message_hash msghf;
	H = msghf (M);

	//convert to bvector
	bvector hash;
	hash.from_bytes (H);

	//check the signature
	tree_hash hf;
	if (Pub.verify (sig, hash, hf)) return 3;

	//otherwise the sig is okay!
	return 0;
}

template<class treehash, class generator, int hs, int h, int l>
static int fmtseq_create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	fmtseq::pubkey Pub;
	fmtseq::privkey Priv;

	treehash hf;
	generator g;

	if (fmtseq::generate (Pub, Priv, rng, hf, g, hs, h, l))
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}


/*
 * actual instantiations
 */

#define fmtseq_create_funcs(name, h, l, hs, message_hash, tree_hash, generator) \
int algo_fmtseq##name::sign (const bvector&msg, \
                             bvector&sig, \
                             sencode**privkey, \
                             bool&dirty, \
                            prng&rng) \
{ \
	return fmtseq_generic_sign \
	       <h, l, hs, message_hash, tree_hash, generator> \
	       (msg, sig, privkey, dirty, rng); \
} \
int algo_fmtseq##name::verify (const bvector&sig, \
                               const bvector&msg, \
                               sencode*pubkey) \
{ \
	return fmtseq_generic_verify \
	       <h, l, hs, message_hash, tree_hash> \
	       (sig, msg, pubkey); \
} \
int algo_fmtseq##name::create_keypair (sencode**pub, sencode**priv, prng&rng) \
{ \
	return fmtseq_create_keypair<tree_hash, generator, hs, h, l> \
	       (pub, priv, rng); \
}


#include "chacha.h"

#if HAVE_CRYPTOPP==1

#include "sha_hash.h"
#include "rmd_hash.h"
#include "tiger_hash.h"


fmtseq_create_funcs (128, 4, 4, 256, sha256hash, rmd128hash, chacha20)
fmtseq_create_funcs (192, 4, 4, 384, sha384hash, tiger192hash, chacha20)
fmtseq_create_funcs (256, 4, 4, 512, sha512hash, sha256hash, chacha20)

/*
 * h=20 variants for signature count 1048576.
 *
 * Chosen were parameters h=4,l=5 over the h=5,l=4 variant for smaller runtime
 * space needed, as signature time is not really a concern here.
 */

fmtseq_create_funcs (128h20, 4, 5, 256, sha256hash, rmd128hash, chacha20)
fmtseq_create_funcs (192h20, 4, 5, 384, sha384hash, tiger192hash, chacha20)
fmtseq_create_funcs (256h20, 4, 5, 512, sha512hash, sha256hash, chacha20)

#endif //HAVE_CRYPTOPP==1

/*
 * CubeHash variants of everything above.
 */

#include "cube_hash.h"

fmtseq_create_funcs (128cube, 4, 4, 256, cube256hash, cube128hash, chacha20)
fmtseq_create_funcs (192cube, 4, 4, 384, cube384hash, cube192hash, chacha20)
fmtseq_create_funcs (256cube, 4, 4, 512, cube512hash, cube256hash, chacha20)

/*
 * h=20 variants with cubehash.
 */

fmtseq_create_funcs (128h20cube, 4, 5, 256, cube256hash, cube128hash, chacha20)
fmtseq_create_funcs (192h20cube, 4, 5, 384, cube384hash, cube192hash, chacha20)
fmtseq_create_funcs (256h20cube, 4, 5, 512, cube512hash, cube256hash, chacha20)

