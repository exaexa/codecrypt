
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

#include <iostream>

/*
 * main module. Parse options, fire up stuff, pass commands to it.
 */

#define out(x) std::cout << x << std::endl
#define outeol std::cout << std::endl
#define err(x) std::cerr << x << std::endl
#define erreol std::cerr << std::endl

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
	out (" -h, --help         display this help");
	out (" -V,--version          display version information");
}

#include <getopt.h>

int main (int argc, char**argv)
{
	bool do_help = false;
	bool do_version = false;
	bool has_opt = false;

	//process options
	int c, option_index;
	for (;;) {
		static struct option long_opts[] = {
			{"help",	0,	0,	'h' },
			{"version",	0,	0,	'V' },
			{0,		0,	0,	0 }
		};

		c = getopt_long (argc, argv, "hV", long_opts, &option_index);
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
	return 0;
}

