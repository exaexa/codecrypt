
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

#include "message.h"

int encrypted_msg::encrypt (const bvector&msg,
                            const std::string& Alg_id,
                            const std::string& Key_id,
                            algorithm_suite&algs, keyring&kr, prng&rng)
{
	key_id = Key_id;
	alg_id = Alg_id;

	algorithm*alg = NULL;
	if (algs.count (alg_id) ) {
		alg = algs[alg_id];
		if (!alg->provides_encryption() )
			alg = NULL;
	}

	if (!alg) return 1;

	sencode*pubkey = kr.get_pubkey (key_id);
	if (!pubkey) return 2; //PK not found

	return alg->encrypt (msg, ciphertext, pubkey, rng);
}

int encrypted_msg::decrypt (bvector& msg, algorithm_suite&algs, keyring& kr)
{
	algorithm*alg = NULL;
	if (algs.count (alg_id) ) {
		alg = algs[alg_id];
		if (!alg->provides_encryption() )
			alg = NULL;
	}

	if (!alg) return 1;

	sencode*privkey = kr.get_privkey (key_id);
	if (!privkey) return 2;

	return alg->decrypt (ciphertext, msg, privkey);
}

int signed_msg::sign (const bvector&msg,
                      const std::string& Alg_id,
                      const std::string& Key_id,
                      algorithm_suite&algs, keyring&kr, prng&rng)
{
	key_id = Key_id;
	alg_id = Alg_id;
	message = msg;

	algorithm*alg = NULL;
	if (algs.count (alg_id) ) {
		alg = algs[alg_id];
		if (!alg->provides_signatures() )
			alg = NULL;
	}

	if (!alg) return 1;

	sencode*privkey = kr.get_privkey (key_id);
	if (!privkey) return 2;

	bool privkey_dirty = false;
	int r;

	r = alg->sign (message, signature, privkey, privkey_dirty, rng);

	if (r) return r;

	//make sure the modified privkey gets stored correctly
	//TODO

	return 0;
}

int signed_msg::verify (algorithm_suite&algs, keyring&kr)
{
	algorithm*alg = NULL;
	if (algs.count (alg_id) ) {
		alg = algs[alg_id];
		if (!alg->provides_signatures() )
			alg = NULL;
	}

	if (!alg) return 1;

	sencode*pubkey = kr.get_pubkey (key_id);
	if (!pubkey) return 2;

	return alg->verify (signature, message, pubkey);
}

