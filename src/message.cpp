
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

#include "mce_qd.h"

int encrypted_msg::encrypt (const bvector&msg,
                            const std::string& Alg_id, const std::string& Key_id,
                            keyring&kr, prng&rng)
{
	key_id = Key_id;
	alg_id = Alg_id;

	sencode*pubkey = kr.get_pubkey (key_id);
	if (!pubkey) return 1; //PK not found

	if (alg_id == "MCEQD-128") {
	} else if (alg_id == "MCEQD-256") {
		mce_qd::pubkey pk;
		if (!pk.unserialize (pubkey) ) return 3; //Key unreadable

		//TODO fujisaki-okamoto
	} else return 2; //unknown algorithm

	return 0;
}

int encrypted_msg::decrypt (bvector&msg, keyring&kr)
{
	sencode*privkey = kr.get_privkey (key_id);
	if (!privkey) return 1; //no key found

	if (alg_id == "MCEQD-128") {
	} else if (alg_id == "MCEQD-256") {
		mce_qd::privkey sk;
		if (!sk.unserialize (privkey) ) return 3; //key unreadable

		//TODO fujisaki-okamoto
	} else return 2; //unknown algorithm

	return 0;
}

int signed_msg::sign (const bvector&msg,
                      const std::string& Alg_id, const std::string&Key_id,
                      keyring&kr, prng&rng)
{
	key_id = Key_id;
	alg_id = Alg_id;
	message = msg;

	sencode*privkey = kr.get_privkey (key_id);
	if (!privkey) return 1;

	if (alg_id == "FMTSEQ-S256-128") {

	} else if (alg_id == "FMTSEQ-S256-256") {

		//TODO produce a reasonable signature
	} else return 2; //unknown algorithm

}

int signed_msg::verify (keyring&kr)
{
	sencode*pubkey = kr.get_pubkey (key_id);
	if (!pubkey) return 1;
	if (alg_id == "FMTSEQ-S256-128") {

		//TODO check it
	} else if (alg_id == "FMTSEQ-S256-256") {

	} else return 2; //unknown algorithm

	return 0;
}

