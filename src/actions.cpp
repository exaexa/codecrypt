
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
                 keyring&KR, algorithm_suite&AS)
{
	return 0;
}


int action_verify (bool armor, const std::string&detach,
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

int action_list (bool nice_fingerprint, const std::string&filter,
                 keyring&KR)
{
	return 0;
}


int action_import (bool armor, bool no_action, bool yes,
                   const std::string&filter, const std::string&name,
                   keyring&KR)
{
	return 0;
}


int action_export (bool armor,
                   const std::string&filter, const std::string&name,
                   keyring&KR)
{
	return 0;
}


int action_delete (bool yes, const std::string&filter, keyring&KR)
{
	return 0;
}


int action_rename (bool yes,
                   const std::string&filter, const std::string&name,
                   keyring&KR)
{
	return 0;
}



int action_list_sec (bool nice_fingerprint, const std::string&filter,
                     keyring&KR)
{
	for (keyring::keypair_storage::iterator
	     i = KR.pairs.begin(), e = KR.pairs.end();
	     i != e; ++i) {

		if (!keyspec_matches (filter, i->second.pub.name, i->first) )
			continue;

		if (!nice_fingerprint)
			out ("keypair\t"
			     << i->second.pub.alg << '\t'
			     << '@' << i->first.substr (0, 22) << "...\t"
			     << "\"" << i->second.pub.name << "\"");
		else {
			out ("key pair with algorithm " << i->second.pub.alg
			     << ", name `" << i->second.pub.name << "'");

			std::cout << "  fingerprint ";
			for (size_t j = 0; j < i->first.length(); ++j) {
				std::cout << i->first[j];
				if (! ( (j + 1) % 4) &&
				    j < i->first.length() - 1)
					std::cout << ':';
			}
			std::cout << std::endl << std::endl;
		}
	}
	return 0;
}


int action_import_sec (bool armor, bool no_action, bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&KR)
{
	return 0;
}


int action_export_sec (bool armor,
                       const std::string&filter, const std::string&name,
                       keyring&KR)
{
	return 0;
}


int action_delete_sec (bool yes, const std::string&filter, keyring&KR)
{
	return 0;
}


int action_rename_sec (bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&KR)
{
	return 0;
}
