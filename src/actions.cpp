
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

#include "actions.h"

#include "iohelpers.h"
#include "generator.h"
#include "str_match.h"
#include "envelope.h"
#include "base64.h"
#include "message.h"

#include <list>

#define ENVELOPE_SECRETS "secrets"
#define ENVELOPE_PUBKEYS "publickeys"
#define ENVELOPE_ENC "encrypted"
#define ENVELOPE_SIG "signed"
//...

int action_gen_key (const std::string& algspec, const std::string&name,
                    keyring&KR, algorithm_suite&AS)
{
	if (algspec == "help") {
		//provide overview of algorithms available
		err ("available algorithms:");
		std::string tag = "     ";
		for (algorithm_suite::iterator i = AS.begin(), e = AS.end();
		     i != e; ++i) {
			tag[1] = i->second->provides_signatures() ? 'S' : '-';
			tag[3] = i->second->provides_encryption() ? 'E' : '-';
			out (tag << i->first);
		}
		return 0;
	}

	algorithm*alg = NULL;
	std::string algname;
	for (algorithm_suite::iterator i = AS.begin(), e = AS.end();
	     i != e; ++i) {
		if (algorithm_name_matches (algspec, i->first) ) {
			if (!alg) {
				algname = i->first;
				alg = i->second;
			} else {
				err ("error: algorithm name `" << algspec
				     << "' matches multiple algorithms");
				return 1;
			}
		}
	}

	if (!alg) {
		err ("error: no such algorithm");
		return 1;
	}

	if (!name.length() ) {
		err ("error: no key name provided");
		return 1;
	}

	sencode *pub, *priv;
	arcfour_rng r;

	err ("Gathering random seed bits from kernel...");
	err ("If nothing happens, move mouse, type random stuff on keyboard,");
	err ("or just wait longer.");

	r.seed (512, false);

	err ("Seeding done, generating the key...");

	if (alg->create_keypair (&pub, &priv, r) ) {
		err ("error: key generator failed");
		return 1;
	}

	KR.store_keypair (keyring::get_keyid (pub), name, algname, pub, priv);
	//pub&priv data will get destroyed along with keyring

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}

/*
 * signatures/encryptions
 */

int action_encrypt (const std::string&recipient, bool armor,
                    keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_decrypt (bool armor,
                    keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_sign (const std::string&user, bool armor, const std::string&detach,
                 bool clearsign, keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_verify (bool armor, const std::string&detach, bool clearsign,
                   keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_sign_encrypt (const std::string&user, const std::string&recipient,
                         bool armor, keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_decrypt_verify (bool armor, keyring&KR, algorithm_suite&AS)
{
	return 0;
}


/*
 * keyring stuff
 */

static void output_key (bool fp,
                        const std::string& ident, const std::string&longid,
                        const std::string&alg, const std::string&keyid,
                        const std::string&name)
{

	if (!fp)
		out (ident << '\t' << alg << '\t'
		     << '@' << keyid.substr (0, 22) << "...\t"
		     << "\"" << name << "\"");
	else {
		out ( longid << " with algorithm " << alg
		      << ", name `" << name << "'");

		std::cout << "  fingerprint ";
		for (size_t j = 0; j < keyid.length(); ++j) {
			std::cout << keyid[j];
			if (! ( (j + 1) % 4) &&
			    j < keyid.length() - 1)
				std::cout << ':';
		}
		std::cout << std::endl << std::endl;
	}
}

int action_list (bool nice_fingerprint, const std::string&filter,
                 keyring&KR)
{
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {

		if (keyspec_matches (filter, i->second.pub.name, i->first) )

			output_key (nice_fingerprint,
			            "pubkey", "public key in keypair",
			            i->second.pub.alg, i->first,
			            i->second.pub.name);
	}

	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) )
			output_key (nice_fingerprint,
			            "pubkey", "public key",
			            i->second.alg, i->first,
			            i->second.name);
	}
	return 0;
}


int action_import (bool armor, bool no_action, bool yes, bool fp,
                   const std::string&filter, const std::string&name,
                   keyring&KR)
{
	std::string data;
	read_all_input (data);

	if (armor) {
		std::string type;
		std::vector<std::string> parts;
		if (!envelope_read (data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_SECRETS || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}

		if (!base64_decode (parts[0], data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*S = sencode_decode (data);
	if (!S) {
		err ("error: could not parse input sencode");
		return 1;
	}

	keyring::pubkey_storage p;
	if (!keyring::parse_pubkeys (S, p) ) {
		err ("error: could not parse input structure");
		return 1;
	}
	sencode_destroy (S);

	if (!p.size() ) {
		err ("notice: keyring was empty");
		return 0;
	}

	if (no_action) {
		for (keyring::pubkey_storage::iterator
		     i = p.begin(), e = p.end(); i != e; ++i) {
			if (keyspec_matches (filter, i->second.name,
			                     i->first) )
				output_key (fp,
				            "pubkey", "public key",
				            i->second.alg, i->first,
				            i->second.name);
		}
		return 0;
	}

	//informatively count how much stuff is this going to destroy.
	int rewrites = 0, privs = 0;
	for (keyring::pubkey_storage::iterator
	     i = p.begin(), e = p.end(); i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) ) {
			if (KR.pairs.count (i->first) ) {
				++privs;
				++rewrites;
			} else if (KR.pubs.count (i->first) ) {
				++rewrites;
			}
		}
	}

	if (rewrites && !yes) {
		err ("error: this would overwrite "
		     << rewrites << " of your keys "
		     "(including " << privs << " private keys). "
		     "Use Yes option to confirm.");
		return 1;
	}

	//merge into KR. Also prevent keyID collisions
	for (keyring::pubkey_storage::iterator
	     i = p.begin(), e = p.end(); i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) ) {
			KR.remove_pubkey (i->first);
			KR.remove_keypair (i->first);
			KR.store_pubkey (i->first, i->second.name,
			                 i->second.alg, i->second.key);
		}
	}

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}


int action_export (bool armor,
                   const std::string & filter, const std::string & name,
                   keyring & KR)
{
	keyring::pubkey_storage s;

	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) ) {
			s[i->first] = i->second.pub;
			if (name.length() )
				s[i->first].name = name;
		}
	}

	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) ) {
			s[i->first] = i->second;
			if (name.length() )
				s[i->first].name = name;
		}
	}

	if (!s.size() ) {
		err ("error: no such public keys");
		return 1;
	}

	sencode*S = keyring::serialize_pubkeys (s);
	if (!S) return 1;
	std::string data = S->encode();
	sencode_destroy (S);

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		arcfour_rng r;
		r.seed (128);
		data = envelope_format (ENVELOPE_PUBKEYS, parts, r);
	}

	out_bin (data);

	return 0;
}


int action_delete (bool yes, const std::string & filter, keyring & KR)
{
	int kc = 0;
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) )
			++kc;
	}
	if (!kc) {
		err ("no such key");
		return 0;
	}
	if (kc > 1 && !yes) {
		bool okay = false;
		ask_for_yes (okay, "This will delete " << kc
		             << " pubkeys from your keyring. Continue?");
		if (!okay) return 0;
	}

	//all clear, delete them
	std::list<std::string> todel;
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) )
			todel.push_back (i->first);
	}

	for (std::list<std::string>::iterator
	     i = todel.begin(), e = todel.end(); i != e; ++i)
		KR.remove_pubkey (*i);

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}


int action_rename (bool yes,
                   const std::string & filter, const std::string & name,
                   keyring & KR)
{
	if (name.length() ) {
		err ("error: missing new name specification");
		return 1;
	}
	int kc = 0;
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) )
			++kc;
	}
	if (!kc) {
		err ("error: no such key");
		return 0;
	}
	if (kc > 1 && !yes) {
		bool okay = false;
		ask_for_yes (okay, "This will rename " << kc
		             << " pubkeys from your keyring to `"
		             << name << "'. Continue?");
		if (!okay) return 0;
	}

	//do the renaming
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.name, i->first) )
			i->second.name = name;
	}

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}



int action_list_sec (bool nice_fingerprint, const std::string & filter,
                     keyring & KR)
{
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {

		if (keyspec_matches (filter, i->second.pub.name, i->first) )
			output_key (nice_fingerprint,
			            "keypair", "key pair",
			            i->second.pub.alg, i->first,
			            i->second.pub.name);
	}
	return 0;
}


int action_import_sec (bool armor, bool no_action, bool yes, bool fp,
                       const std::string & filter, const std::string & name,
                       keyring & KR)
{
	std::string data;
	read_all_input (data);

	if (armor) {
		std::string type;
		std::vector<std::string> parts;
		if (!envelope_read (data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_SECRETS || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}

		if (!base64_decode (parts[0], data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*S = sencode_decode (data);
	if (!S) {
		err ("error: could not parse input sencode");
		return 1;
	}

	keyring::keypair_storage s;
	if (!keyring::parse_keypairs (S, s) ) {
		err ("error: could not parse input structure");
		return 1;
	}
	sencode_destroy (S);

	if (!s.size() ) {
		err ("notice: keyring was empty");
		return 0;
	}

	if (no_action) {
		for (keyring::keypair_storage::iterator
		     i = s.begin(), e = s.end(); i != e; ++i) {
			if (keyspec_matches (filter, i->second.pub.name,
			                     i->first) )
				output_key (fp,
				            "keypair", "key pair",
				            i->second.pub.alg, i->first,
				            i->second.pub.name);
		}
		return 0;
	}

	int rewrites = 0;
	for (keyring::keypair_storage::iterator
	     i = s.begin(), e = s.end(); i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first)
		    && (KR.pubs.count (i->first)
		        || KR.pairs.count (i->first) ) )
			++rewrites;
	}

	if (rewrites && !yes) {
		err ("error: this would overwrite "
		     << rewrites << " of your keys. "
		     "Use Yes option to confirm.");
		return 1;
	}

	//merge into KR. Also prevent keyID collisions
	for (keyring::keypair_storage::iterator
	     i = s.begin(), e = s.end(); i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) ) {
			KR.remove_pubkey (i->first);
			KR.remove_keypair (i->first);
			KR.store_keypair (i->first, i->second.pub.name,
			                  i->second.pub.alg,
			                  i->second.pub.key, i->second.privkey);
		}
	}

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}


int action_export_sec (bool armor, bool yes,
                       const std::string & filter, const std::string & name,
                       keyring & KR)
{
	keyring::keypair_storage s;
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) ) {
			s[i->first] = i->second;
			if (name.length() )
				s[i->first].pub.name = name;
		}
	}

	if (!s.size() ) {
		err ("error: no such secret");
		return 1;
	}

	if (!yes) {
		bool okay = false;
		ask_for_yes (okay, "This will export " << s.size()
		             << " secret keys! Continue?");
		if (!okay) return 0;
	}

	sencode*S = keyring::serialize_keypairs (s);
	if (!S) return 1; //weird.
	std::string data = S->encode();
	sencode_destroy (S);

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		arcfour_rng r;
		r.seed (128);
		data = envelope_format (ENVELOPE_SECRETS, parts, r);
	}

	out_bin (data);

	return 0;
}


int action_delete_sec (bool yes, const std::string & filter, keyring & KR)
{
	int kc = 0;
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) )
			++kc;
	}
	if (!kc) {
		err ("error: no such key");
		return 0;
	}
	if (!yes) {
		bool okay = false;
		ask_for_yes (okay, "This will delete " << kc
		             << " secrets from your keyring. Continue?");
		if (!okay) return 0;
	}

	//all clear, delete them
	std::list<std::string> todel;
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) )
			todel.push_back (i->first);
	}

	for (std::list<std::string>::iterator
	     i = todel.begin(), e = todel.end(); i != e; ++i)
		KR.remove_keypair (*i);

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}


int action_rename_sec (bool yes,
                       const std::string & filter, const std::string & name,
                       keyring & KR)
{
	if (!name.length() ) {
		err ("error: missing new name specification");
		return 1;
	}

	int kc = 0;
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) )
			++kc;
	}
	if (!kc) {
		err ("error: no such key");
		return 0;
	}
	if (!yes) {
		bool okay = false;
		ask_for_yes (okay, "This will rename " << kc
		             << " secrets from your keyring to `"
		             << name << "'. Continue?");
		if (!okay) return 0;
	}

	//do the renaming
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {
		if (keyspec_matches (filter, i->second.pub.name, i->first) )
			i->second.pub.name = name;
	}

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}
	return 0;
}
