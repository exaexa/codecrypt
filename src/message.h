
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

#ifndef _ccr_msg_h_
#define _ccr_msg_h_

#include <string>
#include "bvector.h"
#include "sencode.h"
#include "algorithm.h"
#include "keyring.h"
#include "prng.h"

class encrypted_msg
{
public:
	bvector ciphertext;
	std::string alg_id, key_id;

	int decrypt (bvector&, algorithm_suite&, keyring&);
	int encrypt (const bvector& msg,
	             const std::string& alg_id,
	             const std::string& key_id,
	             algorithm_suite&, keyring&, prng&);

	sencode* serialize();
	bool unserialize (sencode*);
};

class signed_msg
{
public:
	bvector message, signature;
	std::string alg_id, key_id;

	int verify (algorithm_suite&, keyring&);
	int sign (const bvector&msg,
	          const std::string&alg_id,
	          const std::string&key_id,
	          algorithm_suite&, keyring&, prng&);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif

