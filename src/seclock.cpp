
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

#include "seclock.h"

#include "pwrng.h"
#include "iohelpers.h"

#include <sstream>
#include <string>

#include <stdlib.h>

#define LOCKED_PREFIX "ccr_lock"
#define LOCKED_PREFIX_LEN 8

bool looks_like_locked_secret (const std::string&s)
{
	std::string prefix = LOCKED_PREFIX;
	/*
	 * unlocked version of this thing is always some kind of sencode, which
	 * will never start with 'ccr_lock'. Abusing it right here.
	 */
	return s.length() > LOCKED_PREFIX_LEN
	       && s.substr (0, LOCKED_PREFIX_LEN) == LOCKED_PREFIX;
}

bool load_lock_secret (symkey&sk,
                       std::string withlock,
                       const std::string &reason,
                       const std::string &secret_type,
                       bool for_locking)
{
	if (withlock == "") withlock = "@"; //default for password
	if (withlock[0] == '@') {
		//ask the user and generate a symmetric key
		pw_rng r;
		r.init();
		if (!r.seed_from_user_password
		    ( (for_locking ? "locking " : "unlocking ") + reason,
		      "CCR_" + secret_type + "_PASSWORD",
		      for_locking))
			return false;

		withlock.erase (0, 1); //delete the @
		if (withlock.empty()) {
			std::string alg = "CCR_" + secret_type + "_ALGORITHM";
			const char* algorithm = getenv (alg.c_str());
			if (algorithm) withlock = algorithm;
			else withlock = "CHACHA20,CUBE512,SHORTBLOCK";
			//TODO make sure this is synced with synonyms
		}
		return sk.create (withlock, r);
	} else {
		return sk.load (withlock, "", false, false);
	}
}

bool lock_secret (const std::string &secret, std::string &locked,
                  const std::string &withlock,
                  const std::string &reason,
                  const std::string &secret_type,
                  prng&rng)
{

	symkey sk;
	if (!load_lock_secret (sk, withlock, reason, secret_type, true))
		return false;

	std::istringstream i (secret);
	std::ostringstream o;
	o << LOCKED_PREFIX;
	bool ret = sk.encrypt (i, o, rng);
	locked = o.str();
	return ret;
}

bool unlock_secret (const std::string &locked, std::string &secret,
                    const std::string &withlock,
                    const std::string &reason,
                    const std::string &secret_type)
{
	symkey sk;
	if (!looks_like_locked_secret (locked)) {
		err ("seclock: malformed locked secret");
		return false;
	}

	if (!load_lock_secret (sk, withlock, reason, secret_type, false))
		return false;


	std::istringstream i (locked);
	i.ignore (LOCKED_PREFIX_LEN);
	std::ostringstream o;
	bool ret = !sk.decrypt (i, o); //returns int!
	secret = o.str();
	return ret;
}
