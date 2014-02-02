
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

#include <algorithm>
#include <cctype> //for tolower()
using namespace std;

bool algorithm_name_matches (const std::string& search,
                             const std::string&name)
{

	if (search.length() > name.length() ) return false;
	for (size_t i = 0; i < search.length(); ++i)
		if (tolower (search[i]) != tolower (name[i]) ) return false;
	return true;
}

bool matches_icase (string name, string s)
{
	transform (name.begin(), name.end(), name.begin(), ::tolower);
	transform (s.begin(), s.end(), s.begin(), ::tolower);
	return name.find (s) != name.npos;
}

bool keyspec_matches (const std::string&search,
                      const std::string&name,
                      const std::string&keyid)
{
	if (!search.length() ) return true;
	if (search[0] == '@') { //match for keyID
		if (search.length() > keyid.length() + 1) return false;
		for (size_t i = 1; i < search.length(); ++i)
			if (tolower (search[i] != tolower (keyid[i - 1]) ) )
				return false;
		return true;
	}

	return matches_icase (name, search);
}
