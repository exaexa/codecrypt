
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
	out ("Copyright (C) 2013 Mirek Kratochvil <exa.exa@gmail.com>");
	out ("This is free software; see the source "
	     "for copying conditions.  There is NO");
	out ("warranty; not even for MERCHANTABILITY "
	     "or FITNESS FOR A PARTICULAR PURPOSE.");
}

void print_help (char*pname)
{
	print_version();
	outeol;
	out ("Usage: " << pname << " [options]");
	outeol;
	out ("Common options:");
	out (" -h, --help     display this help");
	out (" -V, --version  display version information");
	out (" -T, --test     perform (probably nonexistent) testing/debugging stuff");
	outeol;
	out ("Global options:");
	out (" -i, --input   input file, default is stdin");
	out (" -o, --output  output file, default is stdout");
	out (" -a, --armor   use ascii-armored I/O");
	out (" -y, --yes     assume that answer is `yes' everytime");
	outeol;
	out ("Actions:");
	out (" -s, --sign     sign a message");
	out (" -v, --verify   verify a signed message");
	out (" -e, --encrypt  encrypt a message");
	out (" -d, --decrypt  decrypt an encrypted message");
	outeol;
	out ("Action options:");
	out (" -r, --recipient    encrypt for given user");
	out (" -u, --user         use specified secret key");
	out (" -C, --clearsign    work with cleartext signatures");
	out (" -b, --detach-sign  specify file with detached signature");
	outeol;
	out ("Key management:");
	out (" -g, --gen-key        generate specified keypair");
	out (" -k, --list           list matching keys");
	out (" -K, --list-secret");
	out (" -i, --import         import keys (optionally rename them)");
	out (" -I, --import-secret");
	out (" -p, --export         export matching keys");
	out (" -P, --export-secret");
	out (" -x, --delete         delete matching keys");
	out (" -X, --delete-secret");
	out (" -m, --rename         rename matching keys");
	out (" -M, --rename-secret");
	outeol;
	out ("Key management options:");
	out (" -n, --no-action    on import, only show what would be imported");
	out (" -N, --name         specify a new name for renaming");
	out (" -f, --fingerprint  format key IDs nicely for human eyes");
	outeol;
	out ("Codecrypt eats data. Use it with caution.");
	outeol;
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
	bool do_help = false,
	     do_version = false,
	     do_test = false,
	     has_opt = false,
	     opt_armor = false,
	     opt_fingerprint = false,
	     opt_clearsign = false,
	     opt_import_no_action = false;

	std::string recipient, user,
	    input, output,
	    name,
	    action, action_param,
	    detach_sign;

	//process options
	int c, option_index;
	for (;;) {
		static struct option long_opts[] = {
			{"help",	0,	0,	'h' },
			{"version",	0,	0,	'V' },
			{"test",	0,	0,	'T' },

			//global options
			{"armor",	0,	0,	'a' },
			{"yes",		0,	0,	'y' },
			{"recipient",	1,	0,	'r' },
			{"user",	1,	0,	'u' },

			//I/O redirection from default stdin/out
			{"input",	1,	0,	'i' },
			{"output",	1,	0,	'o' },

			//keyring management
			{"list",	2,	0,	'k' },
			{"import",	2,	0,	'i' },
			{"export",	2,	0,	'p' },
			{"delete",	1,	0,	'x' },

			{"list-secret",	2,	0,	'K' },
			{"import-secret", 2,	0,	'I' },
			{"export-secret", 2,	0,	'P' },
			{"delete-secret", 1,	0,	'X' },

			{"gen-key",	1,	0,	'g' },

			{"rename", 	1,	0,	'm' },
			{"rename-secret", 1,	0,	'M' },
			{"name", 	1,	0,	'N' },

			{"fingerprint",	0,	0,	'f' },
			{"no-action",	0,	0,	'n' },

			//actions
			{"sign",	0,	0,	's' },
			{"verify",	0,	0,	'v' },
			{"encrypt",	0,	0,	'e' },
			{"decrypt",	0,	0,	'd' },

			//action options
			{"clearsign",	0,	0,	'C' },
			{"detach-sign",	1,	0,	'b' },

			{0,		0,	0,	0 }
		};

		c = getopt_long
		    (argc, argv,
		     "hVTayr:u:i:o:k::i::p::x:K::I::P::X:g:m:M:N:fnsvedCb:",
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

