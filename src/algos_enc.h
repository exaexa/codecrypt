
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

#ifndef _ccr_enc_algs_h_
#define _ccr_enc_algs_h_

#include "algorithm.h"

#define mceqd_alg_class(name,alg_id) \
class algo_mceqd##name : public algorithm \
{ \
public: \
	bool provides_signatures() { \
		return false; \
	} \
	bool provides_encryption() { \
		return true; \
	} \
	std::string get_alg_id() { \
		return (alg_id); \
	} \
	int encrypt (const bvector&plain, bvector&cipher, \
	             sencode* pubkey, prng&rng); \
	int decrypt (const bvector&cipher, bvector&plain, \
	             sencode* privkey); \
	int create_keypair (sencode**pub, sencode**priv, prng&rng); \
}

#if HAVE_CRYPTOPP==1

/*
 * SHA-based variants
 */

mceqd_alg_class (128, "MCEQD128FO-SHA256-ARCFOUR");
mceqd_alg_class (192, "MCEQD192FO-SHA384-ARCFOUR");
mceqd_alg_class (256, "MCEQD256FO-SHA512-ARCFOUR");
mceqd_alg_class (128cha, "MCEQD128FO-SHA256-CHACHA20");
mceqd_alg_class (192cha, "MCEQD192FO-SHA384-CHACHA20");
mceqd_alg_class (256cha, "MCEQD256FO-SHA512-CHACHA20");
mceqd_alg_class (128xs, "MCEQD128FO-SHA256-XSYND");
mceqd_alg_class (192xs, "MCEQD192FO-SHA384-XSYND");
mceqd_alg_class (256xs, "MCEQD256FO-SHA512-XSYND");

#endif //HAVE_CRYPTOPP==1

/*
 * Cubehash-based variants
 */

mceqd_alg_class (128cube, "MCEQD128FO-CUBE256-ARCFOUR");
mceqd_alg_class (192cube, "MCEQD192FO-CUBE384-ARCFOUR");
mceqd_alg_class (256cube, "MCEQD256FO-CUBE512-ARCFOUR");
mceqd_alg_class (128cubecha, "MCEQD128FO-CUBE256-CHACHA20");
mceqd_alg_class (192cubecha, "MCEQD192FO-CUBE384-CHACHA20");
mceqd_alg_class (256cubecha, "MCEQD256FO-CUBE512-CHACHA20");
mceqd_alg_class (128cubexs, "MCEQD128FO-CUBE256-XSYND");
mceqd_alg_class (192cubexs, "MCEQD192FO-CUBE384-XSYND");
mceqd_alg_class (256cubexs, "MCEQD256FO-CUBE512-XSYND");

#endif

