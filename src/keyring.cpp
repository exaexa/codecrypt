
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
 * ${CCR_DIR}/pubkeys
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
 *   ( "key-name" pubkey_in_string_encoded_as_sencode )
 *   ( "key-name" pubkey_in_... )
 *   ( "key-name" pubkey )
 *   ...
 * )
 *
 * Reason for pubkeys not to be _embedded_ in sencode is for simpler KeyID
 * computation. We'd either need too much encoding/decoding or some ugly magic
 * otherwise.
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
	if (tmp) return std::string (tmp);
	const char*home = getenv ("HOME");
	if (home) return std::string (home) + "/.ccr";
	return "./.ccr"; //fallback for desolate systems
}

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <fstream>

#define SECRETS_FILENAME "/secrets"
#define PUBKEYS_FILENAME "/pubkeys"


/*
 * prepares the user directory with empty files and similar stuff.
 *
 * We try to setup file permissions properly here and don't care about it later
 * (so that the user can override the default value by easy unixy way)
 */
static bool ensure_empty_sencode_file (const std::string&fn, mode_t mode)
{
	struct stat st;
	if (stat (fn.c_str(), &st) ) {
		if (errno != ENOENT)
			return false;

		//if it simply doesn't exist, create it
		sencode_list l;
		std::string emptyfile = l.encode();

		int fd, res;
		fd = creat (fn.c_str(), mode);
		if (fd < 0) return false;
		res = write (fd, emptyfile.c_str(), emptyfile.length() );
		if (close (fd) ) return false;
		if (res != emptyfile.length() ) return false;

	} else {
		if (!S_ISREG (st.st_mode) )
			return false;
	}

	if (access (fn.c_str(), R_OK | W_OK) ) return false;

	return true;
}

static bool prepare_user_dir (const std::string&dir)
{
	//try to create the directory
	mkdir (dir.c_str(), 0777);

	//and no matter what, verify it's there
	struct stat st;
	if (stat (dir.c_str(), &st) )
		return false;

	if (!S_ISDIR (st.st_mode) )
		return false;

	//create empty key storages, if not present
	std::string fn;

	ensure_empty_sencode_file (dir + PUBKEYS_FILENAME, S_IRUSR | S_IWUSR);
	ensure_empty_sencode_file (dir + SECRETS_FILENAME, S_IRUSR | S_IWUSR);
	return true; //seems m'kay
}

static bool file_get_sencode (const std::string&fn, sencode**out)
{
	//check whether it is a file first
	struct stat st;
	if (stat (fn.c_str(), &st) )
		return false;

	if (!S_ISREG (st.st_mode) )
		return false;

	//not we got the size, prepare buffer space
	std::string data;
	data.resize (st.st_size, 0);

	std::ifstream in (fn.c_str(), std::ios::in | std::ios::binary);
	if (!in) return false;
	in.read (&data[0], st.st_size);
	in.close();

	if (!sencode_decode (data, out) )
		return false;

	return true;
}

static bool file_put_sencode (const std::string&fn, sencode*in)
{
	std::string data = in->encode();

	std::ofstream out (fn.c_str(), std::ios::out | std::ios::binary);
	if (!out) return false;
	out.write (data.c_str(), data.length() );
	if (!out.good() ) return false;
	out.close();
	if (!out.good() ) return false;

	return true;
}

bool keyring::load()
{
	std::string dir = get_user_dir();
	std::string fn;
	sencode_list*L;

	/*
	 * pubkeys loading
	 */
	fn = dir + PUBKEYS_FILENAME;
	sencode* pubkeys;
	if (!file_get_sencode (fn, &pubkeys) )
		return false;

	L = dynamic_cast<sencode_list*> (pubkeys);
	if (!L) goto pubkeys_fail;

	//parse all pubkey entries
	for (std::vector<sencode*>::iterator
	     i = L->items.begin(), e = L->items.end();
	     i != e; ++i) {

		sencode_list*entry = dynamic_cast<sencode_list*> (*i);
		if (!entry) goto pubkeys_fail;

		if (entry->items.size() != 2) goto pubkeys_fail;

		sencode_bytes
		*ident = dynamic_cast<sencode_bytes*> (entry->items[0]),
		 *pubkey = dynamic_cast<sencode_bytes*> (entry->items[1]);

		if (! (ident && pubkey) ) goto pubkeys_fail;

		std::string keyid = get_keyid (pubkey->b);
		sencode*key;
		if (!sencode_decode (pubkey->b, &key) )
			goto pubkeys_fail;

		pubs[keyid] = pubkey_entry (keyid, ident->b, key);
	}

	sencode_destroy (pubkeys);


	/*
	 * keypairs loading
	 */

	fn = dir + SECRETS_FILENAME;
	sencode*keypairs;
	if (!file_get_sencode (fn, &keypairs) )
		return false;

	L = dynamic_cast<sencode_list*> (keypairs);
	if (!L) goto keypairs_fail;

	//entries
	for (std::vector<sencode*>::iterator
	     i = L->items.begin(), e = L->items.end();
	     i != e; ++i) {

		sencode_list*entry = dynamic_cast<sencode_list*> (*i);
		if (!entry) goto keypairs_fail;
		if (entry->items.size() != 3) goto keypairs_fail;

		sencode_bytes
		*ident = dynamic_cast<sencode_bytes*> (entry->items[0]),
		 *privkey = dynamic_cast<sencode_bytes*> (entry->items[1]),
		  *pubkey = dynamic_cast<sencode_bytes*> (entry->items[2]);

		if (! (ident && privkey && pubkey) ) goto keypairs_fail;

		std::string keyid = get_keyid (pubkey->b);
		sencode *priv, *pub;
		if (!sencode_decode (privkey->b, &priv) )
			goto keypairs_fail;
		if (!sencode_decode (pubkey->b, &pub) ) {
			sencode_destroy (priv);
			goto keypairs_fail;
		}

		pairs[keyid] = keypair_entry (keyid, ident->b, pub, priv);
	}


	sencode_destroy (keypairs);
	return true;

pubkeys_fail:
	sencode_destroy (pubkeys);
	return false;

keypairs_fail:
	sencode_destroy (keypairs);
	return false;
}

bool keyring::save()
{
	std::string dir, fn;
	sencode_list*L;
	bool res;

	dir = get_user_dir();

	/*
	 * pubkeys
	 */
	L = new sencode_list();
	for (std::map<std::string, pubkey_entry>::iterator
	     i = pubs.begin(), e = pubs.end();
	     i != e; ++i) {
		sencode_list*a = new sencode_list();
		a->items.resize (2);
		a->items[0] = new sencode_bytes (i->second.name);
		a->items[1] = new sencode_bytes (i->second.key->encode() );
		L->items.push_back (a);
	}

	//save them
	fn = dir + PUBKEYS_FILENAME;
	res = file_put_sencode (fn, L);
	sencode_destroy (L);
	if (!res) return false;

	/*
	 * keypairs
	 */

	L = new sencode_list();
	for (std::map<std::string, keypair_entry>::iterator
	     i = pairs.begin(), e = pairs.end();
	     i != e; ++i) {
		sencode_list*a = new sencode_list;
		a->items.resize (3);
		a->items[0] = new sencode_bytes (i->second.pub.name);
		a->items[1] = new sencode_bytes (i->second.privkey->encode() );
		a->items[2] = new sencode_bytes (i->second.pub.key->encode() );
		L->items.push_back (a);
	}

	//save
	fn = dir + SECRETS_FILENAME;
	res = file_put_sencode (fn, L);
	sencode_destroy (L);
	if (!res) return false;

	return true;
}

bool keyring::open()
{
	//ensure the existence of file structure


	//create the lock


}

bool keyring::close()
{
	//close the lock

}
