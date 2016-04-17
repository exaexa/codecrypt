
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

#ifndef _ccr_enc_algs_h_
#define _ccr_enc_algs_h_

#include "algorithm.h"

#define mce_alg_class(name,alg_id) \
class algo_mce##name : public algorithm \
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

mce_alg_class (qd128, "MCEQD128FO-SHA256-ARCFOUR");
mce_alg_class (qd192, "MCEQD192FO-SHA384-ARCFOUR");
mce_alg_class (qd256, "MCEQD256FO-SHA512-ARCFOUR");
mce_alg_class (qd128cha, "MCEQD128FO-SHA256-CHACHA20");
mce_alg_class (qd192cha, "MCEQD192FO-SHA384-CHACHA20");
mce_alg_class (qd256cha, "MCEQD256FO-SHA512-CHACHA20");
mce_alg_class (qd128xs, "MCEQD128FO-SHA256-XSYND");
mce_alg_class (qd192xs, "MCEQD192FO-SHA384-XSYND");
mce_alg_class (qd256xs, "MCEQD256FO-SHA512-XSYND");

mce_alg_class (qcmdpc128, "MCEQCMDPC128FO-SHA256-ARCFOUR");
mce_alg_class (qcmdpc256, "MCEQCMDPC256FO-SHA512-ARCFOUR");
mce_alg_class (qcmdpc128cha, "MCEQCMDPC128FO-SHA256-CHACHA20");
mce_alg_class (qcmdpc256cha, "MCEQCMDPC256FO-SHA512-CHACHA20");
mce_alg_class (qcmdpc128xs, "MCEQCMDPC128FO-SHA256-XSYND");
mce_alg_class (qcmdpc256xs, "MCEQCMDPC256FO-SHA512-XSYND");

#endif //HAVE_CRYPTOPP==1

/*
 * Cubehash-based variants
 */

mce_alg_class (qd128cube, "MCEQD128FO-CUBE256-ARCFOUR");
mce_alg_class (qd192cube, "MCEQD192FO-CUBE384-ARCFOUR");
mce_alg_class (qd256cube, "MCEQD256FO-CUBE512-ARCFOUR");
mce_alg_class (qd128cubecha, "MCEQD128FO-CUBE256-CHACHA20");
mce_alg_class (qd192cubecha, "MCEQD192FO-CUBE384-CHACHA20");
mce_alg_class (qd256cubecha, "MCEQD256FO-CUBE512-CHACHA20");
mce_alg_class (qd128cubexs, "MCEQD128FO-CUBE256-XSYND");
mce_alg_class (qd192cubexs, "MCEQD192FO-CUBE384-XSYND");
mce_alg_class (qd256cubexs, "MCEQD256FO-CUBE512-XSYND");

mce_alg_class (qcmdpc128cube, "MCEQCMDPC128FO-CUBE256-ARCFOUR");
mce_alg_class (qcmdpc256cube, "MCEQCMDPC256FO-CUBE512-ARCFOUR");
mce_alg_class (qcmdpc128cubecha, "MCEQCMDPC128FO-CUBE256-CHACHA20");
mce_alg_class (qcmdpc256cubecha, "MCEQCMDPC256FO-CUBE512-CHACHA20");
mce_alg_class (qcmdpc128cubexs, "MCEQCMDPC128FO-CUBE256-XSYND");
mce_alg_class (qcmdpc256cubexs, "MCEQCMDPC256FO-CUBE512-XSYND");
#endif

