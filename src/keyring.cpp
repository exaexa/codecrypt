
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

#include "keyring.h"

sencode* keyring::get_pubkey (const std::string&key_id)
{

}

void keyring::remove_pubkey (const std::string&key_id)
{

}

bool keyring::store_pubkey (const std::string&key_id, sencode*)
{

}

sencode* keyring::get_privkey (const std::string&key_id)
{

}

void keyring::remove_privkey (const std::string&key_id)
{

}

bool keyring::store_privkey (const std::string&key_id, sencode*)
{

}

/*
 * DISK KEYRING STORAGE
 *
 * Whole thing is stored in two files just like in GnuPG:
 *
 * ~/.ccr/pubkeys
 * ~/.ccr/private_keyring
 *
 * format of the files is raw sencode.
 *
 * Public key file is organized as follows:
 *
 * (
 *   "ccr public key storage"
 *   ( "public-key-id" pubkey_as_embedded_sencode )
 *   ( "public-key-id" pubkey_as_embedded_sencode )
 *   ( "public-key-id" pubkey_as_embedded_sencode )
 *   ...
 * )
 *
 * Private keys are stored together with their pubkeys, so that they don't have
 * to be generated everytime user asks for them:
 *
 * (
 *   "ccr private keyring"
 *   ( "public-key-id" privkey pubkey )
 *   ( "public-key-id" privkey pubkey )
 *   ( "public-key-id" privkey pubkey )
 *   ...
 * )
 *
 */

bool keyring::disk_sync()
{
	return false;
}
