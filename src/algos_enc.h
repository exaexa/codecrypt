
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

class algo_mceqd128 : public algorithm
{
public:
	bool provides_signatures() {
		return false;
	}

	bool provides_encryption() {
		return true;
	}

	std::string get_alg_id() {
		return "MCEQD128FO-SHA256-ARCFOUR";
	}

	int encrypt (const bvector&plain, bvector&cipher,
	             sencode* pubkey, prng&rng);
	int decrypt (const bvector&cipher, bvector&plain,
	             sencode* privkey);
	int create_keypair (sencode**pub, sencode**priv, prng&rng);
};

class algo_mceqd192 : public algorithm
{
public:
	bool provides_signatures() {
		return false;
	}

	bool provides_encryption() {
		return true;
	}

	std::string get_alg_id() {
		return "MCEQD192FO-SHA384-ARCFOUR";
	}

	int encrypt (const bvector&plain, bvector&cipher,
	             sencode* pubkey, prng&rng);
	int decrypt (const bvector&cipher, bvector&plain,
	             sencode* privkey);
	int create_keypair (sencode**pub, sencode**priv, prng&rng);
};

class algo_mceqd256 : public algorithm
{
public:
	bool provides_signatures() {
		return false;
	}

	bool provides_encryption() {
		return true;
	}

	std::string get_alg_id() {
		return "MCEQD256FO-SHA512-ARCFOUR";
	}

	int encrypt (const bvector&plain, bvector&cipher,
	             sencode* pubkey, prng&rng);
	int decrypt (const bvector&cipher, bvector&plain,
	             sencode* privkey);
	int create_keypair (sencode**pub, sencode**priv, prng&rng);
};

#endif

