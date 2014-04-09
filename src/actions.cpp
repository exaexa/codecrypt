
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

#include "base64.h"
#include "bvector.h"
#include "envelope.h"
#include "generator.h"
#include "hashfile.h"
#include "hash.h"
#include "iohelpers.h"
#include "message.h"
#include "sc.h"
#include "str_match.h"
#include "symkey.h"

#include <list>

#define ENVELOPE_SECRETS "secrets"
#define ENVELOPE_PUBKEYS "publickeys"
#define ENVELOPE_ENC "encrypted"
#define ENVELOPE_SIG "signed"
#define ENVELOPE_CLEARSIGN "clearsigned"
#define ENVELOPE_DETACHSIGN "detachsign"
#define ENVELOPE_HASHFILE "hashfile"
#define ENVELOPE_SYMKEY "symkey"

#define MSG_CLEARTEXT "MESSAGE-IN-CLEARTEXT"
#define MSG_DETACHED "MESSAGE-DETACHED"

inline bool open_keyring (keyring&KR)
{
	if (!KR.open() ) {
		err ("could not open keyring!");
		return false;
	}
	return true;
}

#define PREPARE_KEYRING if(!open_keyring(KR)) return 1

int action_gen_symkey (const std::string&algspec,
                       const std::string&symmetric, bool armor)
{
	symkey sk;
	ccr_rng r;
	r.seed (256);

	if (!sk.create (algspec, r) ) {
		err ("error: symkey creation failed");
		return 1;
	}

	sencode*SK = sk.serialize();
	std::string data = SK->encode();
	sencode_destroy (SK);

	std::ofstream sk_out;
	sk_out.open (symmetric == "-" ? "/dev/stdout" : symmetric.c_str(),
	             std::ios::out | std::ios::binary);
	if (!sk_out) {
		err ("error: can't open symkey file for writing");
		return 1;
	}

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		data = envelope_format (ENVELOPE_SYMKEY, parts, r);
	}

	sk_out << data;
	if (!sk_out.good() ) {
		err ("error: can't write to symkey file");
		return 1;
	}

	sk_out.close();
	if (!sk_out.good() ) {
		err ("error: couldn't close symkey file");
		return 1;
	}

	return 0;
}

typedef std::map<std::string, std::string> algspectable_t;
algspectable_t& algspectable()
{
	static algspectable_t table;
	static bool init = false;

	if (!init) {
		table["enc"] = "MCEQD128FO-CUBE256-CHACHA20";
		table["enc-strong"] = "MCEQD192FO-CUBE384-CHACHA20";
		table["enc-strongest"] = "MCEQD256FO-CUBE512-CHACHA20";

		table["sig"] = "FMTSEQ128C-CUBE256-CUBE128";
		table["sig-strong"] = "FMTSEQ192C-CUBE384-CUBE192";
		table["sig-strongest"] = "FMTSEQ256C-CUBE512-CUBE256";

		table["sym"] = "chacha20,sha256";
		table["sym-strong"] = "chacha20,xsynd,arcfour,cube512,sha512";

		init = true;
	}

	return table;
}

int action_gen_key (const std::string& p_algspec, const std::string&name,
                    const std::string&symmetric, bool armor,
                    keyring&KR, algorithm_suite&AS)
{
	if (p_algspec == "help") {
		//provide overview of algorithms available
		err ("available algorithms: "
		     "([S]ig., [E]nc., sym. [C]ipher, [H]ash) ");
		std::string tag;
		for (algorithm_suite::iterator i = AS.begin(), e = AS.end();
		     i != e; ++i) {
			tag = " " +
			      std::string (i->second->provides_signatures()
			                   ? "S" : "") +
			      std::string (i->second->provides_encryption()
			                   ? "E" : "") + "\t";
			out (tag << i->first);
		}

		for (streamcipher::suite_t::iterator
		     i = streamcipher::suite().begin();
		     i != streamcipher::suite().end(); ++i)
			out (" C\t" << i->first);

		for (hash_proc::suite_t::iterator
		     i = hash_proc::suite().begin();
		     i != hash_proc::suite().end(); ++i)
			out (" H\t" << i->first);

		err ("following aliases are available for convenience: ");
		for (algspectable_t::iterator i = algspectable().begin(),
		     e = algspectable().end();
		     i != e; ++i)
			err (i->first << " = " << i->second);

		return 0;
	}

	//replace algorithm name on match with alias
	std::string algspec;
	if (algspectable().count (p_algspec) )
		algspec = algspectable() [p_algspec];
	else
		algspec = p_algspec;

	//handle symmetric operation
	if (symmetric.length() )
		return action_gen_symkey (algspec, symmetric, armor);

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
	ccr_rng r;

	err ("Gathering random seed bits from kernel...");
	err ("If nothing happens, move mouse, type random stuff on keyboard,");
	err ("or just wait longer.");

	r.seed (512, false);

	err ("Seeding done, generating the key...");

	if (alg->create_keypair (&pub, &priv, r) ) {
		err ("error: key generator failed");
		return 1;
	}

	PREPARE_KEYRING;

	/*
	 * there is a tiny chance that someone will eventually generate a key
	 * that has a colliding KeyID with anyone else. This is highly
	 * improbable, so apologize nicely in that case.
	 */
	if (!KR.store_keypair (keyring::get_keyid (pub),
	                       name, algname, pub, priv) ) {

		err ("error: new key cannot be saved into the keyring.");
		err ("notice: produced KeyID @" << keyring::get_keyid (pub)
		     << " apparently collides with some other known KeyID!");
		err ("notice: if this is not a bug, magic has just happened!");

		return 1;
	}
	//note that pub&priv sencode data will get destroyed along with keyring

	if (!KR.save() ) {
		err ("error: couldn't save keyring");
		return 1;
	}

	return 0;
}

/*
 * signatures/encryptions
 */

int action_sym_encrypt (const std::string&symmetric, bool armor)
{
	//read the symmetric key first
	std::ifstream sk_in;
	sk_in.open (symmetric == "-" ? "/dev/stdin" : symmetric.c_str(),
	            std::ios::in | std::ios::binary);

	if (!sk_in) {
		err ("error: can't open symkey file");
		return 1;
	}

	std::string sk_data;
	if (!read_all_input (sk_data, sk_in) ) {
		err ("error: can't read symkey");
		return 1;
	}
	sk_in.close();

	if (armor) {
		std::vector<std::string> parts;
		std::string type;
		if (!envelope_read (sk_data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_SYMKEY || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}

		if (!base64_decode (parts[0], sk_data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*SK = sencode_decode (sk_data);
	if (!SK) {
		err ("error: could not parse input sencode");
		return 1;
	}

	symkey sk;
	if (!sk.unserialize (SK) ) {
		err ("error: could not parse input structure");
		return 1;
	}

	sencode_destroy (SK);

	ccr_rng r;
	r.seed (256);

	if (!sk.encrypt (std::cin, std::cout, r) ) {
		err ("error: encryption failed");
		return 1;
	}

	return 0;
}

int action_encrypt (const std::string&recipient, bool armor,
                    const std::string&symmetric,
                    keyring&KR, algorithm_suite&AS)
{
	if (symmetric.length() )
		return action_sym_encrypt (symmetric, armor);

	//first, read plaintext
	std::string data;
	read_all_input (data);

	//find a recipient
	keyring::pubkey_entry *recip = NULL;

	PREPARE_KEYRING;

	//search both publickeys and keypairs that are valid for encryption
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end(); i != e; ++i) {
		if (keyspec_matches (recipient, i->second.name, i->first) ) {
			if (!AS.count (i->second.alg) ) continue;
			if (!AS[i->second.alg]->provides_encryption() )
				continue;

			if (recip) {
				err ("error: ambiguous recipient specified");
				return 1;
			} else recip = & (i->second);
		}
	}

	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end(); i != e; ++i) {
		if (keyspec_matches (recipient, i->second.pub.name, i->first) ) {
			if (!AS.count (i->second.pub.alg) ) continue;
			if (!AS[i->second.pub.alg]->provides_encryption() )
				continue;

			if (recip) {
				err ("error: ambiguous recipient specified");
				return 1;
			} else recip = & (i->second.pub);
		}
	}

	if (!recip) {
		err ("error: no such recipient with suitable pubkey");
		return 1;
	}

	//encryption part
	encrypted_msg msg;
	ccr_rng r;
	r.seed (256);

	bvector plaintext;
	plaintext.from_string (data);

	if (msg.encrypt (plaintext, recip->alg, recip->keyid, AS, KR, r) ) {
		err ("error: encryption failed");
		return 1;
	}

	sencode*M = msg.serialize();
	data = M->encode();
	sencode_destroy (M);

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		data = envelope_format (ENVELOPE_ENC, parts, r);
	}

	out_bin (data);
	return 0;
}


int action_sym_decrypt (const std::string&symmetric, bool armor)
{
	std::ifstream sk_in;
	sk_in.open (symmetric == "-" ? "/dev/stdin" : symmetric.c_str(),
	            std::ios::in | std::ios::binary);

	if (!sk_in) {
		err ("error: can't open symkey file");
		return 1;
	}

	std::string sk_data;
	if (!read_all_input (sk_data, sk_in) ) {
		err ("error: can't read symkey");
		return 1;
	}
	sk_in.close();

	if (armor) {
		std::vector<std::string> parts;
		std::string type;
		if (!envelope_read (sk_data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_SYMKEY || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}

		if (!base64_decode (parts[0], sk_data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*SK = sencode_decode (sk_data);
	if (!SK) {
		err ("error: could not parse input sencode");
		return 1;
	}

	symkey sk;
	if (!sk.unserialize (SK) ) {
		err ("error: could not parse input structure");
		return 1;
	}

	sencode_destroy (SK);

	int ret = sk.decrypt (std::cin, std::cout);

	if (ret) err ("error: decryption failed");
	return ret;
}

int action_decrypt (bool armor, const std::string&symmetric,
                    keyring&KR, algorithm_suite&AS)
{
	if (symmetric.length() )
		return action_sym_decrypt (symmetric, armor);

	std::string data;
	read_all_input (data);

	if (armor) {
		std::string type;
		std::vector<std::string> parts;
		if (!envelope_read (data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_ENC || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}
		if (!base64_decode (parts[0], data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*M = sencode_decode (data);
	if (!M) {
		err ("error: could not parse input sencode");
		if (!armor && envelope_lookalike (data) )
			err ("notice: input looks ascii-armored, "
			     "try using the armor option");
		return 1;
	}

	encrypted_msg msg;
	if (!msg.unserialize (M) ) {
		err ("error: could not parse input structure");
		sencode_destroy (M);
		return 1;
	}

	sencode_destroy (M);

	PREPARE_KEYRING;

	//check if we have the privkey
	keyring::keypair_entry*kpe;
	kpe = KR.get_keypair (msg.key_id);
	if (!kpe) {
		err ("error: decryption privkey unavailable");
		err ("info: requires key @" << msg.key_id);
		return 2; //missing key flag
	}

	//and the algorithm
	if ( (!AS.count (msg.alg_id) )
	     || (!AS[msg.alg_id]->provides_encryption() ) ) {
		err ("error: decryption algorithm unsupported");
		err ("info: requires algorithm " << msg.alg_id
		     << " with encryption support");
		return 1;
	}


	//actual decryption
	bvector plaintext;
	if (msg.decrypt (plaintext, AS, KR) ) {
		err ("error: decryption failed");
		return 1;
	}

	if (!plaintext.to_string (data) ) {
		err ("error: malformed data");
		return 1;
	}

	//SEEMS OKAY, let's print some info.
	err ("incoming encrypted message details:");
	err ("  algorithm: " << msg.alg_id);
	err ("  recipient: @" << msg.key_id);
	err ("  recipient local name: `" << kpe->pub.name << "'");

	/*
	 * because there's no possibility to distinguish encrypted from
	 * sign+encrypted messages, just try to parse a message out of this,
	 * and if it comes out, give user a hint.
	 */
	M = sencode_decode (data);
	if (M) {
		signed_msg m;
		if (m.unserialize (M) ) {
			err ("notice: message content looks signed");
			err ("hint: try also decrypt+verify operation");
		}
		sencode_destroy (M);
	}

	//finally pump the decrypted stuff to stdout
	out_bin (data);

	return 0;
}

int action_hash_sign (bool armor, const std::string&symmetric)
{
	hashfile hf;
	if (!hf.create (std::cin) ) {
		err ("error: hashing failed");
		return 1;
	}

	sencode*H = hf.serialize();
	std::string data = H->encode();
	sencode_destroy (H);

	std::ofstream hf_out;
	hf_out.open (symmetric == "-" ? "/dev/stdout" : symmetric.c_str(),
	             std::ios::out | std::ios::binary);
	if (!hf_out) {
		err ("error: can't open hashfile for writing");
		return 1;
	}

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		ccr_rng r;
		r.seed (128);
		data = envelope_format (ENVELOPE_HASHFILE, parts, r);
	}

	hf_out << data;
	if (!hf_out.good() ) {
		err ("error: can't write to hashfile");
		return 1;
	}

	hf_out.close();
	if (!hf_out.good() ) {
		err ("error: couldn't close hashfile");
		return 1;
	}

	return 0;
}

int action_sign (const std::string&user, bool armor, const std::string&detach,
                 bool clearsign, const std::string&symmetric,
                 keyring&KR, algorithm_suite&AS)
{
	//symmetric processing has its own function
	if (symmetric.length() )
		return action_hash_sign (armor, symmetric);

	/*
	 * check detach/armor/clearsign validity first.
	 * Allowed combinations are:
	 *  - nothing
	 *  - armor
	 *  - detach
	 *  - armor+detach
	 *  - clearsign (which is always armored)
	 */

	if (clearsign && (detach.length() || armor) ) {
		err ("error: clearsign cannot be combined "
		     "with armor or detach-sign");
		return 1;
	}

	std::ofstream detf;
	if (detach.length() ) {
		detf.open (detach == "-" ? "/dev/stdout" : detach.c_str(),
		           std::ios::out | std::ios::binary);
		if (!detf) {
			err ("error: can't open detached signature file");
			return 1;
		}
	}

	//eat data for signature
	std::string data;
	read_all_input (data);

	PREPARE_KEYRING;

	//some common checks on user key
	keyring::keypair_entry *u = NULL;

	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end(); i != e; ++i) {
		if (keyspec_matches (user, i->second.pub.name, i->first) ) {
			/*
			 * also match having signature alg availability,
			 * because it saves time when you only have one locally
			 * available signature privkey. Also, no need to check
			 * it again later.
			 */
			if (!AS.count (i->second.pub.alg) ) continue;
			if (!AS[i->second.pub.alg]->provides_signatures() )
				continue;

			if (u) {
				err ("error: ambiguous local user specified");
				return 1;
			} else u = & (i->second);
		}
	}

	if (!u) {
		err ("error: no such supported local privkey");
		return 1;
	}

	//signature production part
	signed_msg msg;
	ccr_rng r;
	r.seed (256);

	bvector message;
	message.from_string (data);

	if (msg.sign (message, u->pub.alg, u->pub.keyid, AS, KR, r) ) {
		err ("error: digital signature failed");
		return 1;
	}

	//now deal with all the output possibilities

	if (clearsign) {
		std::vector<std::string> parts;
		parts.resize (2);

		msg.message.to_string (parts[0]);
		msg.message.from_string (MSG_CLEARTEXT);

		sencode*M = msg.serialize();
		base64_encode (M->encode(), parts[1]);
		sencode_destroy (M);

		out_bin (envelope_format (ENVELOPE_CLEARSIGN, parts, r) );

	} else if (detach.length() ) {
		msg.message.from_string (MSG_DETACHED);
		sencode*M = msg.serialize();
		data = M->encode();
		sencode_destroy (M);

		if (armor) {
			std::vector<std::string> parts;
			parts.resize (1);
			base64_encode (data, parts[0]);
			data = envelope_format (ENVELOPE_DETACHSIGN, parts, r);
		}

		detf << data;
		if (!detf.good() ) {
			err ("error: could not write detached signature file");
			return 1;
		}
		detf.close();
		if (!detf.good() ) {
			err ("error: could not close detached signature file");
			return 1;
		}

	} else {
		sencode*M = msg.serialize();
		data = M->encode();
		sencode_destroy (M);

		if (armor) {
			std::vector<std::string> parts;
			parts.resize (1);
			base64_encode (data, parts[0]);
			data = envelope_format (ENVELOPE_SIG, parts, r);
		}

		out_bin (data);
	}

	return 0;
}

int action_hash_verify (bool armor, const std::string&symmetric)
{
	// first, input the hashfile
	std::ifstream hf_in;
	hf_in.open (symmetric == "-" ? "/dev/stdin" : symmetric.c_str(),
	            std::ios::in | std::ios::binary);
	if (!hf_in) {
		err ("error: can't open hashfile");
		return 1;
	}

	std::string hf_data;
	if (!read_all_input (hf_data, hf_in) ) {
		err ("error: can't read hashfile");
		return 1;
	}
	hf_in.close();

	if (armor) {
		std::vector<std::string> parts;
		std::string type;
		if (!envelope_read (hf_data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_HASHFILE || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}

		if (!base64_decode (parts[0], hf_data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*H = sencode_decode (hf_data);
	if (!H) {
		err ("error: could not parse input sencode");
		return 1;
	}

	hashfile hf;
	if (!hf.unserialize (H) ) {
		err ("error: could not parse input structure");
		return 1;
	}

	sencode_destroy (H);

	int ret = hf.verify (std::cin);
	if (ret) err ("error: hashfile verification failed");

	return ret;
}

int action_verify (bool armor, const std::string&detach,
                   bool clearsign, bool yes, const std::string&symmetric,
                   keyring&KR, algorithm_suite&AS)
{
	//symmetric processing has its own function
	if (symmetric.length() )
		return action_hash_verify (armor, symmetric);

	/*
	 * check flags validity, open detach if possible
	 */
	if (clearsign && (detach.length() || armor) ) {
		err ("error: clearsign cannot be combined "
		     "with armor or detach-sign");
		return 1;
	}

	std::ifstream detf;
	if (detach.length() ) {
		detf.open (detach == "-" ? "/dev/stdin" : detach.c_str(),
		           std::ios::in | std::ios::binary);
		if (!detf) {
			err ("error: can't open detached signature file");
			return 1;
		}
	}

	/*
	 * read input and unpack the whole thing into message.
	 * Takes a lot of effort. :)
	 */

	signed_msg msg;
	std::string data;

	read_all_input (data);

	if (clearsign) {
		std::string type;
		std::vector<std::string> parts;

		if (!envelope_read (data, 0, type, parts) ) {
			err ("error: no data envelope found");
			return 1;
		}

		if (type != ENVELOPE_CLEARSIGN || parts.size() != 2) {
			err ("error: wrong envelope format");
			return 1;
		}

		std::string sig;
		if (!base64_decode (parts[1], sig) ) {
			err ("error: malformed data");
			return 1;
		}

		sencode*M = sencode_decode (sig);
		if (!M) {
			err ("error: could not parse input sencode");
			return 1;
		}

		if (!msg.unserialize (M) ) {
			err ("error: could not parse input structure");
			sencode_destroy (M);
			return 1;
		}

		sencode_destroy (M);

		std::string tmp;
		if (!msg.message.to_string (tmp) || tmp != MSG_CLEARTEXT) {
			err ("error: malformed cleartext signature");
			return 1;
		}

		msg.message.from_string (parts[0]);

	} else if (detach.length() ) {

		std::string sig;
		if (!read_all_input (sig, detf) ) {
			err ("error: can't read detached signature file");
			return 1;
		}

		detf.close();

		if (armor) {
			std::vector<std::string> parts;
			std::string type;
			if (!envelope_read (sig, 0, type, parts) ) {
				err ("error: no data envelope found");
				return 1;
			}

			if (type != ENVELOPE_DETACHSIGN || parts.size() != 1) {
				err ("error: wrong envelope format");
				return 1;
			}

			if (!base64_decode (parts[0], sig) ) {
				err ("error: malformed data");
				return 1;
			}
		}

		sencode*M = sencode_decode (sig);
		if (!M) {
			err ("error: could not parse input sencode");
			return 1;
		}

		if (!msg.unserialize (M) ) {
			err ("error: could not parse input structure");
			sencode_destroy (M);
			return 1;
		}

		sencode_destroy (M);

		std::string tmp;
		if (!msg.message.to_string (tmp) || tmp != MSG_DETACHED) {
			err ("error: malformed detached signature");
			return 1;
		}

		msg.message.from_string (data);

	} else {
		//classical sig
		if (armor) {
			std::string type;
			std::vector<std::string> parts;

			if (!envelope_read (data, 0, type, parts) ) {
				err ("error: no data envelope found");
				return 1;
			}

			if (type != ENVELOPE_SIG || parts.size() != 1) {
				err ("error: wrong envelope format");
				return 1;
			}

			if (!base64_decode (parts[0], data) ) {
				err ("error: malformed data");
				return 1;
			}
		}

		sencode*M = sencode_decode (data);
		if (!M) {
			err ("error: could not parse input sencode");
			if (!armor && envelope_lookalike (data) )
				err ("notice: input looks ascii-armored, "
				     "try using the armor option");
			return 1;
		}

		if (!msg.unserialize (M) ) {
			err ("error: could not parse input structure");
			sencode_destroy (M);
			return 1;
		}

		sencode_destroy (M);
	}

	//check that the message can be converted to bytes
	if (msg.message.size() & 0x7) {
		err ("error: bad message size");
		return 1;
	}

	PREPARE_KEYRING;

	//check pubkey availability
	keyring::pubkey_entry*pke;
	pke = KR.get_pubkey (msg.key_id);
	if (!pke) {
		err ("error: verification pubkey unavailable");
		err ("info: requires key @" << msg.key_id);
		if (!yes) {
			err ("notice: not displaying unverified message");
			err ("info: to see it, use yes option");
		} else {
			err ("warning: following message is UNVERIFIED");
			msg.message.to_string (data);
			out_bin (data);
		}
		return 2; //missing key flag
	}

	if ( (!AS.count (msg.alg_id) )
	     || (!AS[msg.alg_id]->provides_signatures() ) ) {
		err ("error: verification algorithm unsupported");
		err ("info: requires algorithm " << msg.alg_id
		     << " with signature support");
		return 1;
	}

	//do the verification
	int r = msg.verify (AS, KR);

	err ("incoming signed message details:");
	err ("  algorithm: " << msg.alg_id);
	err ("  signed by: @" << msg.key_id);
	err ("  signed local name: `" << pke->name << "'");
	err ("  verification status: "
	     << (r == 0 ?
	         "GOOD signature ;-)" :
	         "BAD signature :-(") );

	if (r) {
		if (!yes) {
			err ("notice: not displaying unverified message");
			err ("info: to see it, use yes option");
		} else {
			err ("warning: following message is UNVERIFIED");
		}
	}

	if (yes || !r) {
		msg.message.to_string (data);
		out_bin (data);
	}

	if (r) return 3; //verification failed flag
	else return 0;
}

/*
 * Combined functions for Sign+Encrypt and Decrypt+Verify.
 *
 * Mostly a copypasta from above primitives.
 * Keep it that way. :)
 */

int action_sign_encrypt (const std::string&user, const std::string&recipient,
                         bool armor, keyring&KR, algorithm_suite&AS)
{
	/*
	 * Signed+encrypted messages must not have a separate envelope header
	 * (it would leak the information that inner message is signed).
	 */

	//eat al input first
	std::string data;
	read_all_input (data);

	PREPARE_KEYRING;

	//find some good local user
	keyring::keypair_entry *u = NULL;

	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end(); i != e; ++i) {
		if (keyspec_matches (user, i->second.pub.name, i->first) ) {
			if (!AS.count (i->second.pub.alg) ) continue;
			if (!AS[i->second.pub.alg]->provides_signatures() )
				continue;

			if (u) {
				err ("error: ambiguous local user specified");
				return 1;
			} else u = & (i->second);
		}
	}

	if (!u) {
		err ("error: no such supported local privkey");
		return 1;
	}

	//find a recipient (don't waste a signature if it'd fail anyway)
	keyring::pubkey_entry *recip = NULL;

	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end(); i != e; ++i) {
		if (keyspec_matches (recipient, i->second.name, i->first) ) {
			if (!AS.count (i->second.alg) ) continue;
			if (!AS[i->second.alg]->provides_encryption() )
				continue;

			if (recip) {
				err ("error: ambiguous recipient specified");
				return 1;
			} else recip = & (i->second);
		}
	}

	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end(); i != e; ++i) {
		if (keyspec_matches (recipient, i->second.pub.name, i->first) ) {
			if (!AS.count (i->second.pub.alg) ) continue;
			if (!AS[i->second.pub.alg]->provides_encryption() )
				continue;

			if (recip) {
				err ("error: ambiguous recipient specified");
				return 1;
			} else recip = & (i->second.pub);
		}
	}

	if (!recip) {
		err ("error: no such recipient with suitable pubkey");
		return 1;
	}

	//make a signature
	signed_msg smsg;
	ccr_rng r;
	r.seed (256);

	bvector bv;
	bv.from_string (data);

	if (smsg.sign (bv, u->pub.alg, u->pub.keyid, AS, KR, r) ) {
		err ("error: digital signature failed");
		return 1;
	}

	sencode*M = smsg.serialize();
	data = M->encode();
	sencode_destroy (M);

	//encrypt it
	encrypted_msg emsg;
	bv.from_string (data);
	if (emsg.encrypt (bv, recip->alg, recip->keyid, AS, KR, r) ) {
		err ("error: encryption failed");
		return 1;
	}

	M = emsg.serialize();
	data = M->encode();
	sencode_destroy (M);

	if (armor) {
		std::vector<std::string> parts;
		parts.resize (1);
		base64_encode (data, parts[0]);
		data = envelope_format (ENVELOPE_ENC, parts, r);
	}

	out_bin (data);
	return 0;
}


int action_decrypt_verify (bool armor, bool yes,
                           keyring&KR, algorithm_suite&AS)
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

		if (type != ENVELOPE_ENC || parts.size() != 1) {
			err ("error: wrong envelope format");
			return 1;
		}
		if (!base64_decode (parts[0], data) ) {
			err ("error: malformed data");
			return 1;
		}
	}

	sencode*M = sencode_decode (data);
	if (!M) {
		err ("error: could not parse input sencode");
		if (!armor && envelope_lookalike (data) )
			err ("notice: input looks ascii-armored, "
			     "try using the armor option");
		return 1;
	}

	encrypted_msg emsg;
	if (!emsg.unserialize (M) ) {
		err ("error: could not parse input structure");
		sencode_destroy (M);
		return 1;
	}

	sencode_destroy (M);

	PREPARE_KEYRING;

	//check if we will be able to decrypt
	keyring::keypair_entry*kpe;
	kpe = KR.get_keypair (emsg.key_id);
	if (!kpe) {
		err ("error: decryption privkey unavailable");
		err ("info: requires key @" << emsg.key_id);
		return 2; //missing key flag
	}

	if ( (!AS.count (emsg.alg_id) )
	     || (!AS[emsg.alg_id]->provides_encryption() ) ) {
		err ("error: decryption algorithm unsupported");
		err ("info: requires algorithm " << emsg.alg_id
		     << " with encryption support");
		return 1;
	}

	bvector bv;
	if (emsg.decrypt (bv, AS, KR) ) {
		err ("error: decryption failed");
		return 1;
	}

	if (!bv.to_string (data) ) {
		err ("error: malformed data");
		return 1;
	}

	//looks okay, print decryption status
	err ("incoming encrypted message details:");
	err ("  algorithm: " << emsg.alg_id);
	err ("  recipient: @" << emsg.key_id);
	err ("  recipient local name: `" << kpe->pub.name << "'");

	//continue with verification
	M = sencode_decode (data);
	if (!M) {
		err ("error: could not parse input sencode");
		return 1;
	}

	signed_msg smsg;
	if (!smsg.unserialize (M) ) {
		err ("error: could not parse input structure");
		sencode_destroy (M);
		return 1;
	}

	sencode_destroy (M);

	if (smsg.message.size() & 0x7) {
		err ("error: bad message size");
		return 1;
	}

	keyring::pubkey_entry*pke;
	pke = KR.get_pubkey (smsg.key_id);
	if (!pke) {
		err ("error: verification pubkey unavailable");
		err ("info: requires key @" << smsg.key_id);
		if (!yes) {
			err ("notice: not displaying unverified message");
			err ("info: to see it, use yes option");
		} else {
			err ("warning: following message is UNVERIFIED");
			smsg.message.to_string (data);
			out_bin (data);
		}
		return 2; //missing key flag
	}

	if ( (!AS.count (smsg.alg_id) )
	     || (!AS[smsg.alg_id]->provides_signatures() ) ) {
		err ("error: verification algorithm unsupported");
		err ("info: requires algorithm " << smsg.alg_id
		     << " with signature support");
		return 1;
	}

	//do the verification
	int r = smsg.verify (AS, KR);

	err ("incoming signed message details:");
	err ("  algorithm: " << smsg.alg_id);
	err ("  signed by: @" << smsg.key_id);
	err ("  signed local name: `" << pke->name << "'");
	err ("  verification status: "
	     << (r == 0 ?
	         "GOOD signature ;-)" :
	         "BAD signature :-(") );

	if (r) {
		if (!yes) {
			err ("notice: not displaying unverified message");
			err ("info: to see it, use the `yes' option");
		} else {
			err ("warning: following message is UNVERIFIED");
		}
	}

	if (yes || !r) {
		smsg.message.to_string (data);
		out_bin (data);
	}

	if (r) return 3; //verification failed flag
	else return 0;
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
	PREPARE_KEYRING;

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

		if (type != ENVELOPE_PUBKEYS || parts.size() != 1) {
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
		if (!armor && envelope_lookalike (data) )
			err ("notice: input looks ascii-armored, "
			     "try using the armor option");
		return 1;
	}

	keyring::pubkey_storage p;
	if (!keyring::parse_pubkeys (S, p) ) {
		err ("error: could not parse input structure");
		sencode_destroy (S);
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

	PREPARE_KEYRING;

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
			KR.store_pubkey (i->first,
			                 name.length() ?
			                 name : i->second.name,
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
	PREPARE_KEYRING;

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
		ccr_rng r;
		r.seed (128);
		data = envelope_format (ENVELOPE_PUBKEYS, parts, r);
	}

	out_bin (data);

	return 0;
}


int action_delete (bool yes, const std::string & filter, keyring & KR)
{
	PREPARE_KEYRING;

	int kc = 0;
	std::list<std::string> todel;
	for (keyring::pubkey_storage::iterator
	     i = KR.pubs.begin(), e = KR.pubs.end();
	     i != e; ++i)
		if (keyspec_matches (filter, i->second.name, i->first) ) {
			++kc;
			todel.push_back (i->first);
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
	if (!name.length() ) {
		err ("error: missing new name specification");
		return 1;
	}

	PREPARE_KEYRING;

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
	PREPARE_KEYRING;

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
		if (!armor && envelope_lookalike (data) )
			err ("notice: input looks ascii-armored, "
			     "try using the armor option");
		return 1;
	}

	keyring::keypair_storage s;
	if (!keyring::parse_keypairs (S, s) ) {
		err ("error: could not parse input structure");
		sencode_destroy (S);
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

	PREPARE_KEYRING;

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
			KR.store_keypair (i->first,
			                  name.length() ?
			                  name : i->second.pub.name,
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
	PREPARE_KEYRING;

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
		ccr_rng r;
		r.seed (128);
		data = envelope_format (ENVELOPE_SECRETS, parts, r);
	}

	out_bin (data);

	return 0;
}


int action_delete_sec (bool yes, const std::string & filter, keyring & KR)
{
	PREPARE_KEYRING;

	int kc = 0;
	std::list<std::string> todel;
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i)
		if (keyspec_matches (filter, i->second.pub.name, i->first) ) {
			++kc;
			todel.push_back (i->first);
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

	PREPARE_KEYRING;

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
