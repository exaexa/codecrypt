
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

#ifndef _ccr_keys_h_
#define _ccr_keys_h_

#include <string>
#include <map>

#include "sencode.h"

class keyring
{
	int lockfd;
public:
	struct pubkey_entry {
		std::string keyid, name, alg;
		sencode *key;

		pubkey_entry() {
			key = NULL;
		}

		pubkey_entry (const std::string& KID,
		              const std::string& N,
		              const std::string& A,
		              sencode*K) :
			keyid (KID),
			name (N),
			alg (A),
			key (K) {}
	};

	struct keypair_entry {
		pubkey_entry pub;
		sencode *privkey;

		keypair_entry() {
			privkey = NULL;
		}

		keypair_entry (const std::string&KID,
		               const std::string& N,
		               const std::string& A,
		               sencode*PubK,
		               sencode*PrivK)
			: pub (KID, N, A, PubK), privkey (PrivK) {}
	};

	typedef std::map<std::string, pubkey_entry> pubkey_storage;
	typedef std::map<std::string, keypair_entry> keypair_storage;

	pubkey_storage pubs;
	keypair_storage pairs;

	std::string backup_pubs, backup_pairs;

	keyring() {
		lockfd = -1;
	}

	~keyring() {
		clear();
	}

	void clear();

	bool open();
	bool close();
	bool save();

	static std::string get_keyid (const std::string& pubkey);

	static std::string get_keyid (sencode* pubkey) {
		return get_keyid (pubkey->encode());
	}

	static void clear_keypairs (keypair_storage&);
	static void clear_pubkeys (pubkey_storage&);

	static bool parse_keypairs (sencode*, keypair_storage&);
	static sencode* serialize_keypairs (const keypair_storage&);
	static bool parse_pubkeys (sencode*, pubkey_storage&);
	static sencode* serialize_pubkeys (const pubkey_storage&);

	pubkey_entry* get_pubkey (const std::string&keyid) {
		// "own first", but there should not be collisions.
		if (pairs.count (keyid)) return & (pairs[keyid].pub);
		if (pubs.count (keyid)) return & (pubs[keyid]);
		return NULL;
	}

	bool store_pubkey (const std::string&keyid,
	                   const std::string&name,
	                   const std::string&alg,
	                   sencode*key) {

		if (pairs.count (keyid)) return false;
		if (pubs.count (keyid)) return false;
		pubs[keyid] = pubkey_entry (keyid, name, alg, key);
		return true;
	}

	void remove_pubkey (const std::string&keyid) {
		if (pubs.count (keyid)) {
			sencode_destroy (pubs[keyid].key);
			pubs.erase (keyid);
		}
	}

	keypair_entry* get_keypair (const std::string&keyid) {
		if (pairs.count (keyid)) return & (pairs[keyid]);
		return NULL;
	}

	bool store_keypair (const std::string&keyid,
	                    const std::string&name,
	                    const std::string&alg,
	                    sencode*pubkey, sencode*privkey) {

		if (pairs.count (keyid)) return false;
		if (pubs.count (keyid)) return false;
		pairs[keyid] = keypair_entry (keyid, name, alg,
		                              pubkey, privkey);
		return true;
	}

	void remove_keypair (const std::string&keyid) {
		if (pairs.count (keyid)) {
			sencode_destroy (pairs[keyid].pub.key);
			sencode_destroy (pairs[keyid].privkey);
			pairs.erase (keyid);
		}
	}
};

#endif

