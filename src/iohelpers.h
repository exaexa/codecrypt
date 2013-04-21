
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

#ifndef _ccr_iohelpers_h_
#define _ccr_iohelpers_h_

/*
 * output helpers
 */

#include <iostream>
#include <fstream>
#include <string>

#define out(x) std::cout << x << std::endl
#define out_bin(x) std::cout << x
#define outeol std::cout << std::endl
#define err(x) std::cerr << x << std::endl
#define erreol std::cerr << std::endl
#define progerr(x) std::cerr << argv[0] << ": " << x << std::endl

#define ask_for_yes(ok,x) do {std::cerr << x << " (y/n): "; \
	std::string answer; std::cin >> answer; \
	ok=(answer=="y");} while(0)

bool redirect_cin (const std::string& fn);
bool redirect_cout (const std::string& fn);

bool read_all_input (std::string&);

#endif
