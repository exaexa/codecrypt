
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

void keyring::clear()
{
	for (std::map<std::string, pubkey_entry>::iterator
	     i = pubs.begin(), e = pubs.end(); i != e; ++i)
		sencode_destroy (i->second.key);
	pubs.clear();

	for (std::map<std::string, keypair_entry>::iterator
	     i = pairs.begin(), e = pairs.end(); i != e; ++i) {
		sencode_destroy (i->second.pub.key);
		sencode_destroy (i->second.privkey);
	}
	pairs.clear();
}

/*
 * KeyID is SHA256 of pubkey string representation. Also serves as a
 * simple fingerprint.
 */

#include "sha2.h"
#include <stdint.h>

std::string keyring::get_keyid (const std::string&pubkey)
{
	SHA256_CTX ctx;
	uint8_t t;

	SHA256_Init (&ctx);

	for (size_t i = 0; i < pubkey.length(); ++i) {
		t = pubkey[i];
		SHA256_Update (&ctx, &t, 1);
	}

	std::string r;
	r.resize (64, ' ');
	SHA256_End (&ctx, & (r[0]) );

	return r;
}

/*
 * DISK KEYRING STORAGE
 *
 * Whole thing is stored in two files just like in GnuPG:
 *
 * ${CCR_DIR}/pubring
 * ${CCR_DIR}/secrets
 *
 * CCR_DIR is taken from environment, and defaults to ${HOME}/.ccr
 *
 * format of the files is raw sencode.
 *
 * Public key file is organized as follows:
 *
 * (
 *   "ccr public key storage"
 *   ( "key-name" pubkey_as_embedded_sencode )
 *   ( "key-name" pubkey_as_embedded_sencode )
 *   ( "key-name" pubkey_as_embedded_sencode )
 *   ...
 * )
 *
 * Private keys are stored together with their pubkeys, so that they don't have
 * to be generated everytime user asks for them:
 *
 * (
 *   "ccr private keyring"
 *   ( "key-name" privkey pubkey )
 *   ( "key-name" privkey pubkey )
 *   ( "key-name" privkey pubkey )
 *   ...
 * )
 *
 */

#include <stdlib.h>

static std::string get_user_dir()
{
	const char*tmp = getenv ("CCR_DIR");
	if (tmp) return tmp;
	const char*home = getenv ("HOME");
	if (home) return home + "/.ccr";
	return "./.ccr"; //fallback for desolate systems
}

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bool prepare_user_dir (const string&dir)
{
	//try to create the directory
	mkdir (dir.c_str(), 0777);

	//and no matter what, verify it's there
	struct stat st;
	if (stat (dir.c_str(), &st) )
		return false;

	if (!S_ISDIR (st.st_mode) )
		return false;

	return true; //seems m'kay
}

bool keyring::load()
{

}

bool keyring::save()
{

}

bool keyring::open()
{

}

bool keyring::close()
{

}
