
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2017 Mirek Kratochvil <exa.exa@gmail.com>
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
	clear_keypairs (pairs);
	clear_pubkeys (pubs);
}

/*
 * KeyID is CUBE256 of pubkey string representation. Also serves as a
 * simple fingerprint.
 */

#include "cube_hash.h"
#include <inttypes.h>

std::string keyring::get_keyid (const std::string&pubkey)
{
	static const char hex[] = "0123456789abcdef";

	std::string r;

	cube256hash hf;
	std::vector<byte> tmp =
	    hf (std::vector<byte>
	        (pubkey.data(),
	         pubkey.data() + pubkey.length()));

	r.resize (tmp.size() * 2, ' ');
	for (size_t i = 0; i < tmp.size(); ++i) {
		r[2 * i] = hex[ (tmp[i] >> 4) & 0xf];
		r[2 * i + 1] = hex[tmp[i] & 0xf];
	}

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
 *   "CCR-PUBKEYS"
 *   ( "key-name" "algorithm-id" pubkey_in_string_encoded_as_sencode )
 *   ( "key-name" "algorithm-id" pubkey_in_... )
 *   ( "key-name" "algorithm-id" pubkey )
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
 *   "CCR-KEYPAIRS"
 *   ( "key-name" "algorithm-id" privkey pubkey )
 *   ( "key-name" "algorithm-id" privkey pubkey )
 *   ( "key-name" "algorithm-id" privkey pubkey )
 *   ...
 * )
 *
 * --------
 * Serialization stuff first.
 */

#define KEYPAIRS_ID "CCR-KEYPAIRS"
#define PUBKEYS_ID "CCR-PUBKEYS"

void keyring::clear_keypairs (keypair_storage&pairs)
{
	for (std::map<std::string, keypair_entry>::iterator
	     i = pairs.begin(), e = pairs.end(); i != e; ++i) {
		sencode_destroy (i->second.pub.key);
		if (i->second.privkey)
			sencode_destroy (i->second.privkey);
	}
	pairs.clear();
}

void keyring::clear_pubkeys (pubkey_storage&pubs)
{
	for (std::map<std::string, pubkey_entry>::iterator
	     i = pubs.begin(), e = pubs.end(); i != e; ++i)
		sencode_destroy (i->second.key);
	pubs.clear();
}

bool keyring::parse_keypairs (sencode*keypairs, keypair_storage&pairs)
{
	sencode_bytes *ID;
	sencode_list *L;

	clear_keypairs (pairs);

	L = dynamic_cast<sencode_list*> (keypairs);
	if (!L) goto failure;

	if (!L->items.size()) goto failure;
	ID = dynamic_cast<sencode_bytes*> (L->items[0]);
	if (!ID) goto failure;
	if (ID->b != KEYPAIRS_ID) goto failure;

	for (std::vector<sencode*>::iterator
	     i = L->items.begin() + 1, e = L->items.end();
	     i != e; ++i) {

		sencode_list*entry = dynamic_cast<sencode_list*> (*i);
		if (!entry) goto failure;
		if (entry->items.size() != 4) goto failure;

		sencode_bytes
		*ident = dynamic_cast<sencode_bytes*> (entry->items[0]),
		 *alg = dynamic_cast<sencode_bytes*> (entry->items[1]),
		  *privkey = dynamic_cast<sencode_bytes*> (entry->items[2]),
		   *pubkey = dynamic_cast<sencode_bytes*> (entry->items[3]);

		if (! (ident && alg && privkey && pubkey)) goto failure;

		std::string keyid = get_keyid (pubkey->b);
		sencode *pub;

		pub = sencode_decode (pubkey->b);
		if (!pub) goto failure;

		pairs[keyid] = keypair_entry (keyid, ident->b, alg->b,
		                              pub, privkey->b);
	}

	return true;
failure:
	clear_keypairs (pairs);
	return false;
}

sencode* keyring::serialize_keypairs (keypair_storage&pairs, prng&rng)
{
	for (std::map<std::string, keypair_entry>::iterator
	     i = pairs.begin(), e = pairs.end(); i != e; ++i)
		if (!i->second.fix_dirty (rng)) return NULL;

	sencode_list*L = new sencode_list();
	L->items.push_back (new sencode_bytes (KEYPAIRS_ID));

	for (keypair_storage::const_iterator
	     i = pairs.begin(), e = pairs.end();
	     i != e; ++i) {
		sencode_list*a = new sencode_list;
		a->items.resize (4);
		a->items[0] = new sencode_bytes (i->second.pub.name);
		a->items[1] = new sencode_bytes (i->second.pub.alg);
		a->items[2] = new sencode_bytes (i->second.privkey_raw);
		a->items[3] = new sencode_bytes (i->second.pub.key->encode());
		L->items.push_back (a);
	}

	return L;
}

bool keyring::parse_pubkeys (sencode* pubkeys, pubkey_storage&pubs)
{
	sencode_bytes *ID;
	sencode_list *L;

	clear_pubkeys (pubs);

	L = dynamic_cast<sencode_list*> (pubkeys);
	if (!L) goto failure;

	if (!L->items.size()) goto failure;
	ID = dynamic_cast<sencode_bytes*> (L->items[0]);
	if (!ID) goto failure;
	if (ID->b != PUBKEYS_ID) goto failure;

	for (std::vector<sencode*>::iterator
	     i = L->items.begin() + 1, e = L->items.end();
	     i != e; ++i) {

		sencode_list*entry = dynamic_cast<sencode_list*> (*i);
		if (!entry) goto failure;

		if (entry->items.size() != 3) goto failure;

		sencode_bytes
		*ident = dynamic_cast<sencode_bytes*> (entry->items[0]),
		 *alg = dynamic_cast<sencode_bytes*> (entry->items[1]),
		  *pubkey = dynamic_cast<sencode_bytes*> (entry->items[2]);

		if (! (ident && alg && pubkey)) goto failure;

		std::string keyid = get_keyid (pubkey->b);
		sencode*key;
		key = sencode_decode (pubkey->b);
		if (!key) goto failure;

		pubs[keyid] = pubkey_entry (keyid, ident->b, alg->b, key);
	}

	return true;

failure:
	clear_pubkeys (pubs);
	return false;
}

sencode* keyring::serialize_pubkeys (const pubkey_storage&pubs)
{
	sencode_list*L = new sencode_list();
	L->items.push_back (new sencode_bytes (PUBKEYS_ID));

	for (pubkey_storage::const_iterator
	     i = pubs.begin(), e = pubs.end();
	     i != e; ++i) {
		sencode_list*a = new sencode_list();
		a->items.resize (3);
		a->items[0] = new sencode_bytes (i->second.name);
		a->items[1] = new sencode_bytes (i->second.alg);
		a->items[2] = new sencode_bytes (i->second.key->encode());
		L->items.push_back (a);
	}

	return L;
}

/*
 * OS/disk functions
 */

#ifdef WIN32
#define SECRETS_FILENAME "\\secrets"
#define PUBKEYS_FILENAME "\\pubkeys"
#define LOCK_FILENAME "\\lock"
#define CCR_CONFDIR "\\.ccr"
#else
#define SECRETS_FILENAME "/secrets"
#define PUBKEYS_FILENAME "/pubkeys"
#define LOCK_FILENAME "/lock"
#define CCR_CONFDIR "/.ccr"
#endif

#define BAK_SUFFIX "~"

#include <stdlib.h>

static std::string get_user_dir()
{
	const char*tmp = getenv ("CCR_DIR");
	if (tmp) return std::string (tmp);
	const char*home = getenv ("HOME");
	if (home) return std::string (home) + CCR_CONFDIR;
	return "." CCR_CONFDIR; //fallback for absolutely desolate systems
}

#include "privfile.h"
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/*
 * prepares the user directory with empty files and similar stuff.
 *
 * We try to setup file permissions properly here and don't care about it later
 * (so that the user can override the default value by easy unixy way)
 */

static bool ensure_empty_sencode_file (const std::string&fn,
                                       const std::string&ident)
{
	sencode_list l;
	sencode_bytes b (ident);
	l.items.push_back (&b);
	std::string emptyfile = l.encode();

	return put_private_file (fn, emptyfile, true);
}

static bool prepare_user_dir (const std::string&dir)
{
	//try to create the directory, continue if it's already there
#ifdef WIN32
	if (mkdir (dir.c_str())) {
#else
	if (mkdir (dir.c_str(), 0777)) {
#endif
		if (errno != EEXIST) return false;
	}

	//and no matter what, verify it's there
	struct stat st;
	if (stat (dir.c_str(), &st))
		return false;

	//and is really a directory.
	if (!S_ISDIR (st.st_mode))
		return false;

	//finally create empty key storages and backups, if not present
	return ensure_empty_sencode_file (dir + PUBKEYS_FILENAME,
	                                  PUBKEYS_ID) &&
	       ensure_empty_sencode_file (dir + PUBKEYS_FILENAME BAK_SUFFIX,
	                                  PUBKEYS_ID) &&
	       ensure_empty_sencode_file (dir + SECRETS_FILENAME,
	                                  KEYPAIRS_ID) &&
	       ensure_empty_sencode_file (dir + SECRETS_FILENAME BAK_SUFFIX,
	                                  KEYPAIRS_ID);
}

static sencode* file_get_sencode (const std::string&fn,
                                  std::string&data)
{
	//check whether it is a file first
	struct stat st;
	if (stat (fn.c_str(), &st))
		return NULL;

	if (!S_ISREG (st.st_mode))
		return NULL;

	//not we got the size, prepare buffer space
	data.resize (st.st_size, 0);

	std::ifstream in (fn.c_str(), std::ios::in | std::ios::binary);
	if (!in) return NULL;
	in.read (&data[0], st.st_size);
	in.close();

	//and decode it
	return sencode_decode (data);
}

static bool file_put_string (const std::string&fn, const std::string&data)
{
	std::ofstream out (fn.c_str(), std::ios::out | std::ios::binary);
	if (!out) return false;
	out.write (data.c_str(), data.length());
	if (!out.good()) return false;
	out.close();
	if (!out.good()) return false;

	return true;
}

static bool file_put_sencode_with_backup (const std::string&fn, sencode*in,
                                          const std::string&backup_fn,
                                          const std::string&backup_data)
{
	std::string data = in->encode();
	if (data == backup_data) return true; //nothing to do

	return file_put_string (backup_fn, backup_data) &&
	       file_put_string (fn, data);
}

#ifndef WIN32

#include <signal.h>

static void ignore_term_signals (bool ignore)
{
	int signums[] = {
		SIGHUP,
		SIGINT,
		SIGQUIT,
		SIGPIPE,
		SIGTERM,
		SIGUSR1,
		SIGUSR2,
		0
	};

	struct sigaction sa;

	sa.sa_handler = ignore ? SIG_IGN : SIG_DFL;
	sa.sa_flags = 0;

	for (int*sig = signums; *sig; ++sig) {
		sigaction (*sig, &sa, NULL);
	}
}

#else
static void ignore_term_signals (bool ignore)
{
	//no kill resistance on windows yet
}
#endif

bool keyring::save (prng&rng)
{
	std::string dir, fn, bfn;
	sencode*S;
	bool res;

	dir = get_user_dir();

	ignore_term_signals (true);

	/*
	 * pubkeys
	 */
	S = serialize_pubkeys (pubs);
	fn = dir + PUBKEYS_FILENAME;
	bfn = fn + BAK_SUFFIX;
	res = file_put_sencode_with_backup (fn, S, bfn, backup_pubs);
	sencode_destroy (S);
	if (!res) goto failure;

	/*
	 * keypairs
	 */
	S = serialize_keypairs (pairs, rng);
	if (!S) return false;

	fn = dir + SECRETS_FILENAME;
	bfn = fn + BAK_SUFFIX;
	res = file_put_sencode_with_backup (fn, S, bfn, backup_pairs);
	sencode_destroy (S);
	if (!res) goto failure;

	ignore_term_signals (false);
	return true;

failure:
	ignore_term_signals (false);
	return false;
}

bool keyring::open()
{
	//ensure the existence of file structure
	std::string dir = get_user_dir();
	if (!prepare_user_dir (dir)) return false;

	//create the lock
	std::string fn = dir + LOCK_FILENAME;
	lockfd = creat (fn.c_str(), S_IRUSR | S_IWUSR);
	if (lockfd < 0) return false;

#ifdef WIN32
	//no locking on windows yet
#else
	if (flock (lockfd, LOCK_EX)) {
		::close (lockfd);
		lockfd = -1;
		return false;
	}
#endif

	//load the public keys
	fn = dir + PUBKEYS_FILENAME;

	sencode *pubkeys, *keypairs;
	bool res;

	pubkeys = file_get_sencode (fn, backup_pubs);
	if (!pubkeys) goto close_and_fail;

	res = parse_pubkeys (pubkeys, pubs);
	sencode_destroy (pubkeys);
	if (!res) goto close_and_fail;

	//load keypairs
	fn = dir + SECRETS_FILENAME;

	keypairs = file_get_sencode (fn, backup_pairs);
	if (!keypairs) goto close_and_fail;

	res = parse_keypairs (keypairs, pairs);
	sencode_destroy (keypairs);
	if (!res) goto close_and_fail;

	//all okay
	return true;

close_and_fail:
	close();
	return false;
}

bool keyring::close()
{
	/*
	 * close and remove the lock. Because of temporary lack of proper
	 * reporting, we just ignore the errors now.
	 *
	 * Note that unlink goes first, so that the lock disappears atomically.
	 */

	if (lockfd < 0) return true; //nothing to close

	std::string fn = get_user_dir() + LOCK_FILENAME;
	unlink (fn.c_str());

#ifdef WIN32
	//no locking on windows yet
#else
	flock (lockfd, LOCK_UN);
#endif

	::close (lockfd);

	lockfd = -1;

	return true;
}

/*
 * keypair_entry loads the privkeys lazily so that it's not necessary to have
 * all the secrets all the time
 */

#include "seclock.h"
#include "iohelpers.h"

bool keyring::keypair_entry::lock (const std::string&withlock)
{
	//withlock here is useful for just re-encrypting,
	//possibly with different password
	if (!decode_privkey (withlock)) return false;
	err ("notice: locking key @" + pub.keyid);
	if (!load_lock_secret (sk, withlock,
	                       "protecting key `"
	                       + escape_output (pub.name)
	                       + "'",
	                       "KEYRING", true))
		return false;

	dirty = true;
	locked = true;
	return true;
}

bool keyring::keypair_entry::unlock (const std::string&withlock)
{
	if (!decode_privkey (withlock)) return false;
	if (locked) {
		locked = false;
		dirty = true;
	}
	return true;
}

bool keyring::keypair_entry::decode_privkey (const std::string&withlock)
{
	if (privkey) return true; //already done
	std::string encoded;
	if (looks_like_locked_secret (privkey_raw)) {
		err ("notice: unlocking key @" + pub.keyid);
		if (!unlock_secret_sk (privkey_raw, encoded,
		                       withlock,
		                       "loading key `"
		                       + escape_output (pub.name)
		                       + "'",
		                       "KEYRING", sk))
			return false;
		locked = true;
	} else {
		encoded = privkey_raw;
		locked = false;
	}

	privkey = sencode_decode (encoded);
	if (!privkey)
		return false;

	dirty = false;
	return true;
}

#include <sstream>

bool keyring::keypair_entry::fix_dirty (prng&rng)
{
	if (!privkey || !dirty) return true; //nothing to do!
	if (locked) {
		std::string encoded = privkey->encode();
		if (!lock_secret_sk (encoded, privkey_raw, sk, rng))
			return false;
	} else {
		privkey_raw = privkey->encode();
	}
	dirty = false;
	return true;
}
