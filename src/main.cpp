
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

#include "iohelpers.h"

void print_version()
{
	out ("codecrypt " PACKAGE_VERSION);
	out ("Copyright (C) 2014 Mirek Kratochvil <exa.exa@gmail.com>");
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
	out (" -R, --in      input file, default is stdin");
	out (" -o, --out     output file, default is stdout");
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
	out (" -S, --symmetric    enable symmetric mode of operation where encryption");
	out ("                    is done using symmetric cipher and signatures are");
	out ("                    hashes, and specify a filename of symmetric key or hashes");
	outeol;
	out ("Key management:");
	out (" -g, --gen-key        generate specified keypair, `help' lists algorithms");
	out (" -k, --list           list keys");
	out (" -K, --list-secret");
	out (" -i, --import         import keys");
	out (" -I, --import-secret");
	out (" -p, --export         export keys");
	out (" -P, --export-secret");
	out (" -x, --delete         delete matching keys");
	out (" -X, --delete-secret");
	out (" -m, --rename         rename matching keys");
	out (" -M, --rename-secret");
	outeol;
	out ("Key management options:");
	out (" -n, --no-action    on import, only show what would be imported");
	out (" -N, --name         specify a new name for renaming or importing");
	out (" -F, --filter       only work with keys with matching names");
	out (" -f, --fingerprint  format full key IDs nicely for human eyes");
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

#include "actions.h"
#include "algo_suite.h"

int main (int argc, char**argv)
{
	//option variables
	bool do_help = false,
	     do_version = false,
	     do_test = false,
	     has_opt = false,
	     opt_armor = false,
	     opt_yes = false,
	     opt_fingerprint = false,
	     opt_clearsign = false,
	     opt_import_no_action = false;

	std::string recipient, user,
	    input, output,
	    name, filter,
	    action_param,
	    detach_sign,
	    symmetric;

	char action = 0;

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
			{"in",		1,	0,	'R' },
			{"out",		1,	0,	'o' },

			//keyring management
			{"list",	0,	0,	'k' },
			{"import",	0,	0,	'i' },
			{"export",	0,	0,	'p' },
			{"delete",	1,	0,	'x' },
			{"rename", 	1,	0,	'm' },

			{"list-secret",	0,	0,	'K' },
			{"import-secret", 0,	0,	'I' },
			{"export-secret", 0,	0,	'P' },
			{"delete-secret", 1,	0,	'X' },
			{"rename-secret", 1,	0,	'M' },

			{"gen-key",	1,	0,	'g' },

			{"name", 	1,	0,	'N' },
			{"filter", 	1,	0,	'F' },

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
			{"symmetric",	1,	0,	'S' },

			{0,		0,	0,	0 }
		};

		option_index = -1;
		c = getopt_long
		    (argc, argv,
		     "hVTayr:u:R:o:kipx:m:KIPX:M:g:N:F:fnsvedCb:S:",
		     long_opts, &option_index);
		if (c == -1) break;

		has_opt = true;
		switch (c) {
		case '?':
		case ':':
		case 'h':
			do_help = true;
			break;

#define read_flag(ch,var) case ch: var=true; break;

#define read_single_opt(ch,var,errmsg) \
	case ch: if(var.length()) {progerr(errmsg); do_help=true;}\
	else var=optarg; break;

#define read_action(ch) read_action_comb(ch,0,0)

#define read_action_comb(ch, hit, comb) \
	case ch: \
	if(hit && action==hit) { \
		action=comb; \
		if(optarg) action_param=optarg; \
	} else if(action) { \
		progerr("please specify a single action"); \
		do_help=true; \
	} else { \
		action=ch; \
		if(optarg) action_param=optarg; \
	} break;



			read_flag ('V', do_version)
			read_flag ('T', do_test)
			read_flag ('a', opt_armor)
			read_flag ('y', opt_yes)

			read_single_opt ('r', recipient,
			                 "specify only one recipient")
			read_single_opt ('u', user,
			                 "specify only one local user")
			read_single_opt ('R', input,
			                 "cannot accept multiple inputs")
			read_single_opt ('o', output,
			                 "cannot accept multiple outputs")

			read_action ('k')
			read_action ('i')
			read_action ('p')
			read_action ('x')
			read_action ('m')

			read_action ('K')
			read_action ('I')
			read_action ('P')
			read_action ('X')
			read_action ('M')

			read_action ('g')

			read_single_opt ('N', name,
			                 "please specify single name")
			read_single_opt ('F', filter,
			                 "please specify single filter string")

			read_flag ('f', opt_fingerprint)
			read_flag ('n', opt_import_no_action)

			/*
			 * combinations of s+e and d+v are possible. result is
			 * 'E' = "big encrypt with sig" and 'D' "big decrypt
			 * with verify".
			 */
			read_action_comb ('s', 'e', 'E')
			read_action_comb ('v', 'd', 'D')
			read_action_comb ('e', 's', 'E')
			read_action_comb ('d', 'v', 'D')

			read_flag ('C', opt_clearsign)
			read_single_opt ('b', detach_sign,
			                 "specify only one detach-sign file")
			read_single_opt ('S', symmetric,
			                 "specify only one symmetric parameter")

#undef read_flag
#undef read_single_opt
#undef read_action

		default: //which doesn't just happen.
			do_help = true;
			break;
		}
	}

	if (optind != argc) {
		progerr ("unmatched non-option parameters");
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
	 * something will be happening, therefore init everything
	 */

	keyring KR;
	algorithm_suite AS;

	//register all available algorithms
	fill_algorithm_suite (AS);

	/*
	 * cin/cout redirection
	 */

	int exitval = 0;

	if (input.length() && !redirect_cin (input) ) {
		progerr ("could not open input file");
		exitval = 1;
		goto exit;
	}

	if (output.length() && !redirect_cout (output) ) {
		progerr ("could not redirect to output file");
		exitval = 1;
		goto exit;
	}

	/*
	 * check the option flags and do whatever was requested
	 */

	if (do_test) {
		test();
		goto exit;
	}

	if (symmetric.length() ) switch (action) {
		case 'd':
		case 'e':
		case 'g':
		case 's':
		case 'v':
			break;
		default:
			progerr ("specified action doesn't support symmetric operation");
			exitval = 1;
			goto exit;
		}

	switch (action) {
	case 'g':
		exitval = action_gen_key (action_param, name,
		                          symmetric, opt_armor,
		                          KR, AS);
		break;

	case 'e':
		exitval = action_encrypt (recipient, opt_armor, symmetric,
		                          KR, AS);
		break;

	case 'd':
		exitval = action_decrypt (opt_armor, symmetric, KR, AS);
		break;

	case 's':
		exitval = action_sign (user, opt_armor, detach_sign,
		                       opt_clearsign, symmetric, KR, AS);
		break;

	case 'v':
		exitval = action_verify (opt_armor, detach_sign, opt_clearsign,
		                         opt_yes, symmetric, KR, AS);
		break;

	case 'E':
		exitval = action_sign_encrypt (user, recipient, opt_armor,
		                               KR, AS);
		break;

	case 'D':
		exitval = action_decrypt_verify (opt_armor, opt_yes,
		                                 KR, AS);
		break;

	case 'k':
		exitval = action_list (opt_fingerprint, filter, KR);
		break;

	case 'i':
		exitval = action_import (opt_armor, opt_import_no_action,
		                         opt_yes, opt_fingerprint,
		                         filter, name, KR);
		break;

	case 'p':
		exitval = action_export (opt_armor, filter, name, KR);
		break;

	case 'x':
		exitval = action_delete (opt_yes, action_param, KR);
		break;

	case 'm':
		exitval = action_rename (opt_yes, action_param, name, KR);
		break;

	case 'K':
		exitval = action_list_sec (opt_fingerprint, filter, KR);
		break;

	case 'I':
		exitval = action_import_sec (opt_armor, opt_import_no_action,
		                             opt_yes, opt_fingerprint,
		                             filter, name, KR);
		break;

	case 'P':
		exitval = action_export_sec (opt_armor, opt_yes,
		                             filter, name, KR);
		break;

	case 'X':
		exitval = action_delete_sec (opt_yes, action_param, KR);
		break;

	case 'M':
		exitval = action_rename_sec (opt_yes, action_param, name, KR);
		break;

	default:
		progerr ("no action specified, use `--help'");
		exitval = 1;
		break;

	}

	/*
	 * all done.
	 * keyring is _not_ automatically saved here to prevent frequent
	 * rewriting and due the fact that everything that modifies it _must_
	 * also ensure and verify that it was written back correctly.
	 */

exit:
	if (!KR.close() ) {
		progerr ("could not close keyring, "
		         "something weird is going to happen.");
	}

	return exitval;
}

