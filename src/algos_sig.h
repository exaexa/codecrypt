
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

#ifndef _ccr_sig_algs_h_
#define _ccr_sig_algs_h_

#include "algorithm.h"

#define fmtseq_alg_class(name,alg_id) \
class algo_fmtseq##name : public algorithm \
{ \
public: \
	bool provides_signatures() { \
		return true; \
	} \
	bool provides_encryption() { \
		return false; \
	} \
	std::string get_alg_id() { \
		return (alg_id); \
	} \
	virtual int sign (const bvector&msg, bvector&sig, \
	                  sencode** privkey, bool&dirty, prng&rng); \
	virtual int verify (const bvector&sig, const bvector&msg, \
	                    sencode* pubkey); \
	int create_keypair (sencode**pub, sencode**priv, prng&rng); \
}

#if HAVE_CRYPTOPP==1

/*
 * SHA-2 and similar-based variants
 */

fmtseq_alg_class (128, "FMTSEQ128C-SHA256-RIPEMD128");
fmtseq_alg_class (192, "FMTSEQ192C-SHA384-TIGER192");
fmtseq_alg_class (256, "FMTSEQ256C-SHA512-SHA256");
fmtseq_alg_class (128h20, "FMTSEQ128H20C-SHA256-RIPEMD128");
fmtseq_alg_class (192h20, "FMTSEQ192H20C-SHA384-TIGER192");
fmtseq_alg_class (256h20, "FMTSEQ256H20C-SHA512-SHA256");

#endif //HAVE_CRYPTOPP==1


/*
 * Cubehash variants
 */

fmtseq_alg_class (128cube, "FMTSEQ128C-CUBE256-CUBE128");
fmtseq_alg_class (192cube, "FMTSEQ192C-CUBE384-CUBE192");
fmtseq_alg_class (256cube, "FMTSEQ256C-CUBE512-CUBE256");
fmtseq_alg_class (128h20cube, "FMTSEQ128H20C-CUBE256-CUBE128");
fmtseq_alg_class (192h20cube, "FMTSEQ192H20C-CUBE384-CUBE192");
fmtseq_alg_class (256h20cube, "FMTSEQ256H20C-CUBE512-CUBE256");

#endif

