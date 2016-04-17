
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

#include "message.h"

int encrypted_msg::encrypt (const bvector&msg,
                            const std::string& Alg_id,
                            const std::string& Key_id,
                            algorithm_suite&algs, keyring&kr, prng&rng)
{
	key_id = Key_id;
	alg_id = Alg_id;

	algorithm*alg = NULL;
	if (algs.count (alg_id)) {
		alg = algs[alg_id];
		if (!alg->provides_encryption())
			alg = NULL;
	}

	if (!alg) return 1;

	keyring::pubkey_entry*pk = kr.get_pubkey (key_id);
	if (!pk) return 2; //PK not found

	if (pk->alg != alg_id) return 3; //algorithm mismatch

	return alg->encrypt (msg, ciphertext, pk->key, rng);
}

int encrypted_msg::decrypt (bvector& msg, algorithm_suite&algs, keyring& kr)
{
	algorithm*alg = NULL;
	if (algs.count (alg_id)) {
		alg = algs[alg_id];
		if (!alg->provides_encryption())
			alg = NULL;
	}

	if (!alg) return 1;

	keyring::keypair_entry*k = kr.get_keypair (key_id);
	if (!k) return 2;

	if (k->pub.alg != alg_id) return 3;

	return alg->decrypt (ciphertext, msg, k->privkey);
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
	if (algs.count (alg_id)) {
		alg = algs[alg_id];
		if (!alg->provides_signatures())
			alg = NULL;
	}

	if (!alg) return 1;

	keyring::keypair_entry *k = kr.get_keypair (key_id);
	if (!k) return 2;

	if (k->pub.alg != alg_id) return 3;

	bool privkey_dirty = false;
	int r;

	r = alg->sign (message, signature, & (k->privkey), privkey_dirty, rng);

	if (r) return r;

	if (privkey_dirty) {
		//we can't output a signature without storing privkey changes!
		if (!kr.save()) return 4;
	}

	return 0;
}

int signed_msg::verify (algorithm_suite&algs, keyring&kr)
{
	algorithm*alg = NULL;
	if (algs.count (alg_id)) {
		alg = algs[alg_id];
		if (!alg->provides_signatures())
			alg = NULL;
	}

	if (!alg) return 1;

	keyring::pubkey_entry*pk = kr.get_pubkey (key_id);
	if (!pk) return 2;

	if (pk->alg != alg_id) return 3;

	return alg->verify (signature, message, pk->key);
}

