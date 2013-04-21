
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

bool redirect_cin (const std::string& fn)
{
	static std::ifstream alt_cin;
	alt_cin.open (fn.c_str(), std::ios::in | std::ios::binary);
	if (alt_cin.fail() ) return false;
	std::cin.rdbuf (alt_cin.rdbuf() );
	return true;
}

bool redirect_cout (const std::string& fn)
{
	static std::ofstream alt_cout;
	alt_cout.open (fn.c_str(), std::ios::out | std::ios::binary);
	if (alt_cout.fail() ) return false;
	std::cout.rdbuf (alt_cout.rdbuf() );
	return true;
}
