
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

#include "str_match.h"

#include <ctype.h> //for tolower()

bool algorithm_name_matches (const std::string& search,
                             const std::string&name)
{

	if (search.length() > name.length() ) return false;
	for (size_t i = 0; i < search.length(); ++i)
		if (tolower (search[i]) != tolower (name[i]) ) return false;
	return true;
}
