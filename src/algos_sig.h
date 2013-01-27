
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

#ifndef _ccr_sig_algs_h_
#define _ccr_sig_algs_h_

#include "algorithm.h"

class algo_fmtseq128 : public algorithm
{
public:
	bool provides_signatures() {
		return true;
	}

	bool provides_encryption() {
		return false;
	}

	std::string get_alg_id() {
		return "FMTSEQ128-SHA256-RIPEMD128";
	}

	virtual int sign (const bvector&msg, bvector&sig,
	                  sencode* privkey, bool&dirty, prng&rng);
	virtual int verify (const bvector&sig, const bvector&msg,
	                    sencode* pubkey);
	int create_keypair (sencode**pub, sencode**priv, prng&rng);
};

class algo_fmtseq256 : public algorithm
{
public:
	bool provides_signatures() {
		return true;
	}

	bool provides_encryption() {
		return false;
	}

	std::string get_alg_id() {
		return "FMTSEQ256-SHA512-SHA256";
	}

	virtual int sign (const bvector&msg, bvector&sig,
	                  sencode* privkey, bool&dirty, prng&rng);
	virtual int verify (const bvector&sig, const bvector&msg,
	                    sencode* pubkey);
	int create_keypair (sencode**pub, sencode**priv, prng&rng);
};

#endif

