
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

#include "algos_sig.h"

#include "fmtseq.h"
#include "sha_hash.h"
#include "rmd_hash.h"
#include "tiger_hash.h"
#include "arcfour.h"

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

#define min(a,b) ((a)<(b)?(a):(b))

static void msg_pad (const bvector&in, std::vector<byte>&out, size_t minsize)
{
	uint i;

	out.clear();
	out.resize ( ( (in.size() - 1) >> 3) + 1, 0);
	for (i = 0; i < in.size(); ++i)
		if (in[i]) out[i >> 3] |= 1 << (i & 0x7);

	if (out.size() >= minsize) return;

	arcfour<byte> g;
	g.init (8);

	//stuff in as much seed material as possible
	for (i = 0; i < (out.size() >> 8); ++i) {
		std::vector<byte> sub (out.begin() + (i << 8),
		                       min (out.end(),
		                            out.begin() + ( (i + 1) << 8) ) );
		g.load_key (sub);
	}
	g.discard (256);

	i = out.size();
	out.resize (minsize);
	for (; i < minsize; ++i) out[i] = g.gen();
}

/*
 * actual signature stuff.
 */

template <int h, int l, int hs, class message_hash, class tree_hash>
static int fmtseq_generic_sign (const bvector&msg,
                                bvector&sig,
                                sencode**privkey,
                                bool&dirty,
                                prng&rng)
{
	//load the key
	fmtseq::privkey Priv;
	if (!Priv.unserialize (*privkey) ) return 1;

	//check parameters
	if ( (Priv.h != h) || (Priv.l != l)
	     || (Priv.hs != hs) ) return 2;

	//prepare the message and hash it
	std::vector<byte> M, H;
	msg_pad (msg, M, hs);
	message_hash msghf;
	H = msghf (M);

	//convert to bvector
	bvector hash;
	hash.resize (hs, 0);
	for (uint i = 0; i < hs; ++i) hash[i] = 1 & (H[i >> 3] >> (i & 0x7) );

	//make a signature
	tree_hash hf;
	if (Priv.sign (hash, sig, hf) ) return 3;

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
	if (!Pub.unserialize (pubkey) ) return 1;

	//check parameters
	if ( (Pub.H != h * l) || (Pub.hs != hs) ) return 2;

	//prepare the message and hash it
	std::vector<byte> M, H;
	msg_pad (msg, M, hs);
	message_hash msghf;
	H = msghf (M);

	//convert to bvector
	bvector hash;
	hash.resize (hs, 0);
	for (uint i = 0; i < hs; ++i) hash[i] = 1 & (H[i >> 3] >> (i & 0x7) );

	//check the signature
	tree_hash hf;
	if (Pub.verify (sig, hash, hf) ) return 3;

	//otherwise the sig is okay!
	return 0;
}

template<class treehash, int hs, int h, int l>
static int fmtseq_create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	fmtseq::pubkey Pub;
	fmtseq::privkey Priv;

	treehash hf;

	if (fmtseq::generate (Pub, Priv, rng, hf, hs, h, l) )
		return 1;

	*pub = Pub.serialize();
	*priv = Priv.serialize();
	return 0;
}


/*
 * actual instantiations
 */

int algo_fmtseq128::sign (const bvector&msg,
                          bvector&sig,
                          sencode**privkey,
                          bool&dirty,
                          prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 256, sha256hash, rmd128hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq128::verify (const bvector&sig,
                            const bvector&msg,
                            sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 256, sha256hash, rmd128hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq192::sign (const bvector&msg,
                          bvector&sig,
                          sencode**privkey,
                          bool&dirty,
                          prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 384, sha384hash, tiger192hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq192::verify (const bvector&sig,
                            const bvector&msg,
                            sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 384, sha384hash, tiger192hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq256::sign (const bvector&msg,
                          bvector&sig,
                          sencode**privkey,
                          bool&dirty,
                          prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 512, sha512hash, sha256hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq256::verify (const bvector&sig,
                            const bvector&msg,
                            sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 512, sha512hash, sha256hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq128::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<rmd128hash, 256, 4, 4>
	       (pub, priv, rng);
}

int algo_fmtseq192::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<tiger192hash, 384, 4, 4>
	       (pub, priv, rng);
}

int algo_fmtseq256::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<sha256hash, 512, 4, 4>
	       (pub, priv, rng);
}

/*
 * h=20 variants for signature count 1048576.
 *
 * Chosen were parameters h=4,l=5 over the h=5,l=4 variant for smaller runtime
 * space needed, as signature time is not really a concern here.
 */

int algo_fmtseq128h20::sign (const bvector&msg,
                             bvector&sig,
                             sencode**privkey,
                             bool&dirty,
                             prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 256, sha256hash, rmd128hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq128h20::verify (const bvector&sig,
                               const bvector&msg,
                               sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 256, sha256hash, rmd128hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq192h20::sign (const bvector&msg,
                             bvector&sig,
                             sencode**privkey,
                             bool&dirty,
                             prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 384, sha384hash, tiger192hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq192h20::verify (const bvector&sig,
                               const bvector&msg,
                               sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 384, sha384hash, tiger192hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq256h20::sign (const bvector&msg,
                             bvector&sig,
                             sencode**privkey,
                             bool&dirty,
                             prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 512, sha512hash, sha256hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq256h20::verify (const bvector&sig,
                               const bvector&msg,
                               sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 512, sha512hash, sha256hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq128h20::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<rmd128hash, 256, 4, 5>
	       (pub, priv, rng);
}

int algo_fmtseq192h20::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<tiger192hash, 384, 4, 5>
	       (pub, priv, rng);
}

int algo_fmtseq256h20::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<sha256hash, 512, 4, 5>
	       (pub, priv, rng);
}

/*
 * CubeHash variants of everything above.
 */

#include "cube_hash.h"

int algo_fmtseq128cube::sign (const bvector&msg,
                              bvector&sig,
                              sencode**privkey,
                              bool&dirty,
                              prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 256, cube256hash, cube128hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq128cube::verify (const bvector&sig,
                                const bvector&msg,
                                sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 256, cube256hash, cube128hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq192cube::sign (const bvector&msg,
                              bvector&sig,
                              sencode**privkey,
                              bool&dirty,
                              prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 384, cube384hash, cube192hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq192cube::verify (const bvector&sig,
                                const bvector&msg,
                                sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 384, cube384hash, cube192hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq256cube::sign (const bvector&msg,
                              bvector&sig,
                              sencode**privkey,
                              bool&dirty,
                              prng&rng)
{
	return fmtseq_generic_sign
	       <4, 4, 512, cube512hash, cube256hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq256cube::verify (const bvector&sig,
                                const bvector&msg,
                                sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 4, 512, cube512hash, cube256hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq128cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube128hash, 256, 4, 4>
	       (pub, priv, rng);
}

int algo_fmtseq192cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube192hash, 384, 4, 4>
	       (pub, priv, rng);
}

int algo_fmtseq256cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube256hash, 512, 4, 4>
	       (pub, priv, rng);
}

/*
 * h=20 variants with cubehash.
 */

int algo_fmtseq128h20cube::sign (const bvector&msg,
                                 bvector&sig,
                                 sencode**privkey,
                                 bool&dirty,
                                 prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 256, cube256hash, cube128hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq128h20cube::verify (const bvector&sig,
                                   const bvector&msg,
                                   sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 256, cube256hash, cube128hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq192h20cube::sign (const bvector&msg,
                                 bvector&sig,
                                 sencode**privkey,
                                 bool&dirty,
                                 prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 384, cube384hash, cube192hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq192h20cube::verify (const bvector&sig,
                                   const bvector&msg,
                                   sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 384, cube384hash, cube192hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq256h20cube::sign (const bvector&msg,
                                 bvector&sig,
                                 sencode**privkey,
                                 bool&dirty,
                                 prng&rng)
{
	return fmtseq_generic_sign
	       <4, 5, 512, cube512hash, cube256hash>
	       (msg, sig, privkey, dirty, rng);
}

int algo_fmtseq256h20cube::verify (const bvector&sig,
                                   const bvector&msg,
                                   sencode*pubkey)
{
	return fmtseq_generic_verify
	       <4, 5, 512, cube512hash, cube256hash>
	       (sig, msg, pubkey);
}

int algo_fmtseq128h20cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube128hash, 256, 4, 5>
	       (pub, priv, rng);
}

int algo_fmtseq192h20cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube192hash, 384, 4, 5>
	       (pub, priv, rng);
}

int algo_fmtseq256h20cube::create_keypair (sencode**pub, sencode**priv, prng&rng)
{
	return fmtseq_create_keypair<cube256hash, 512, 4, 5>
	       (pub, priv, rng);
}
