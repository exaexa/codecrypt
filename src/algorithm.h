
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

#ifndef _ccr_algorithm_h_
#define _ccr_algorithm_h_

#include "bvector.h"
#include "prng.h"
#include "sencode.h"

#include <map>
#include <string>
class algorithm;
typedef std::map<std::string, algorithm*> algorithm_suite;

//virtual interface definition for all cryptographic algorithm instances
class algorithm
{
public:
	virtual bool provides_signatures() = 0;
	virtual bool provides_encryption() = 0;
	virtual std::string get_alg_id() = 0;

	void register_into_suite (algorithm_suite&s) {
		s[this->get_alg_id()] = this;
	}

	/*
	 * note that these functions should be ready for different
	 * plaintext/ciphertext/message lengths, usually padding them somehow.
	 */
	virtual int encrypt (const bvector&plain, bvector&cipher,
	                     sencode* pubkey, prng&rng) = 0;

	virtual int decrypt (const bvector&cipher, bvector&plain,
	                     sencode* privkey) = 0;

	virtual int sign (const bvector&msg, bvector&sig,
	                  sencode* privkey, bool&dirty,
	                  prng&rng) = 0;

	virtual int verify (const bvector&sig, const bvector&msg,
	                    sencode* pubkey) = 0;

	virtual int create_keypair (sencode**pub, sencode**priv, prng&rng) = 0;
};

#endif

