
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

#include "pwrng.h"

#include "iohelpers.h"
#include <stdlib.h>

#if (HAVE_READPASSPHRASE == 1)
#include <readpassphrase.h>
#elif (HAVE_BSDREADPASSPHRASE == 1)
#include <bsd/readpassphrase.h>
#else
#warning "Falling back to getpass(3), which is marked obsolete!"
/* If you see this, you might as well want to take the readpassphrase()
 * implementation from e.g. openssh's openbsd-compat and put it here. */
#include <unistd.h>
#endif

#define MAX_PW_LEN 1024 //like if someone enjoyed typing that.

static bool read_password (const std::string&prompt, std::string&pw)
{
#if (HAVE_READPASSPHRASE == 1 || HAVE_BSDREADPASSPHRASE==1)
	/* readpassphrase reads at most bufsiz-1 bytes and gets the terminating
	 * zero just right */
	std::vector<char> pwbuf;
	pwbuf.resize (MAX_PW_LEN, 0);
	if (!readpassphrase (prompt.c_str(), pwbuf.data(), MAX_PW_LEN,
	                     RPP_REQUIRE_TTY))
		return false;

	pw = pwbuf.data();
	return true;
#else
	char* pass = getpass (prompt.c_str());
	if (!pass) return false;
	pw = pass;
	return true;
#endif
}

bool pw_rng::seed_from_user_password (const std::string&reason,
                                      const std::string&env_var,
                                      bool verify)
{

	std::string pw;

	const char*env = getenv (env_var.c_str());
	if (env) {
		pw = env;
		err ("Password for "
		     << reason
		     << " successfully read from environment "
		     << env_var);
	} else {
		if (!read_password
		    ("Enter password for " + reason + ": ", pw)) {
			err ("pwrng: interactive password reading failed");
			return false;
		}

		if (verify) {
			std::string pw2;
			if (!read_password
			    ("Same password again for verification: ",
			     pw2)) {
				err ("pwrng: password verification failed");
				return false;
			}
			if (pw != pw2) {
				err ("Passwords do not match!");
				return false;
			}
		}
	}

	r.load_key ( (byte*) pw.data(),
	             (byte*) (pw.data() + pw.length()));
	return true;
}
