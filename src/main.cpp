
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

#include "outhelpers.h"

void print_version()
{
	out ("codecrypt " PACKAGE_VERSION);
}

void print_help (char*pname)
{
	print_version();
	outeol;
	out ("Usage: " << pname << " [options]");
	outeol;
	out ("Options consist of:");
	out (" -h, --help            display this help");
	out (" -V,--version          display version information");
	out (" -T                    perform some testing stuff");
}

/*
 * testing
 */

void test()
{
	/*
	 * Dear hacker,
	 * use this function for quicktesting your stuff.
	 * Other places suck for that purpose.
	 */
}

/*
 * main module. Parse options, fire up stuff, pass commands to it.
 */

#include <getopt.h>

#include "keyring.h"

int main (int argc, char**argv)
{
	bool do_help = false;
	bool do_version = false;
	bool do_test = false;
	bool has_opt = false;

	//process options
	int c, option_index;
	for (;;) {
		static struct option long_opts[] = {
			{"help",	0,	0,	'h' },
			{"version",	0,	0,	'V' },
			{"test",	0,	0,	'T' },

			//global options
			{"armor",	0,	0,	'a' },
			{"recipient",	1,	0,	'r' },
			{"user",	1,	0,	'u' },

			//I/O redirection from default stdin/out
			{"input",	1,	0,	'i' },
			{"output",	1,	0,	'o' },

			//keyring management
			{"list",	2,	0,	'k' },
			{"import",	2,	0,	0 },
			{"export",	2,	0,	0 },
			{"delete",	1,	0,	0 },

			{"list-secret",	2,	0,	'K' },
			{"import-secret", 2,	0,	0 },
			{"export-secret", 2,	0,	0 },
			{"delete-secret", 1,	0,	0 },

			{"gen-key",	1,	0,	0 }

			{"rename", 	2,	0,	0 },
			{"name", 	2,	0,	0 },

			{"fingerprint",	0,	0,	0 },

			//actions
			{"sign",	0,	0,	's' },
			{"verify",	0,	0,	'v' },
			{"encrypt",	0,	0,	'e' },
			{"decrypt",	0,	0,	'd' },

			//action options
			{"clearsign",	0,	0,	0 },
			{"detach-sign",	1,	0,	'b' },

			{0,		0,	0,	0 }
		};

		c = getopt_long (argc, argv, "hVTar:u:i:o:k::K::svedb:",
		                 long_opts, &option_index);
		if (c == -1) break;

		has_opt = true;
		switch (c) {
		case '?':
		case ':':
		case 'h':
			do_help = true;
			break;
		case 'V':
			do_version = true;
			break;
		case 'T':
			do_test = true;
			break;
		default: //which doesn't just happen.
			break;
		}
	}

	if (optind != argc) {
		err (argv[0] << ": unmatched non-option parameters");
		do_help = true;
	}

	if ( (!has_opt) || do_help) {
		print_help (argv[0]);
		return 0;
	}

	if (do_version) {
		print_version();
		return 0;
	}

	/*
	 * something is happening here, therefore init everything
	 */

	int exitflag = 0;

	keyring KR;

	if (!KR.open() ) {
		err ("could not open keyring!");
		return 1;
	}

	if (!KR.load() ) {
		err ("could not load keyring!");
		exitflag = 1;
		goto exit_ok;
	}

	/*
	 * check the option flags and do whatever was requested
	 */

	if (do_test) {
		test();
		goto exit_ok;
	}

	/*
	 * all done.
	 * keyring is _not_ automatically saved here to prevent frequent
	 * rewriting and due the fact that everything that modifies it _must_
	 * also ensure and verify that it was written back correctly.
	 */

exit_ok:
	if (!KR.close() ) {
		err ("could not close keyring, "
		     "something weird is going to happen.");
	}

	return exitflag;
}

