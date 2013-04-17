
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

#include "envelope.h"

/*
 * how do the ascii envelopes look like?
 *
 * similarly to PGP:
 *
 * ------ccr begin typeident termident------
 * data
 * ------ccr cut typeident termident------
 * next part data
 * ------ccr cut typeident termident------
 * other next part data
 * ------ccr end typeident termident------
 *
 * To distinguish ourselves from PGP, we use six dashes and prefixed CCR name.
 * No version information is supplied - versioning should be contained
 * preferably in typeident, e.g. like "message" "better_message" and
 * "bettermessage-version3".
 *
 * Cleartext two-part messages and similar evil sorceries are generalized to
 * multipart messages using the "part cut".
 *
 * Also, to prevent cleartext embedding conflicts, we add termident, which is
 * basically a random string of letters and numbers that serves as a mark that
 * must be the same on the begin and end.
 */

size_t envelope_get (const std::string&data, size_t offset,
                     std::string&out_type,
                     std::vector<std::string>&out_parts)
{

	size_t begin;

restart:
	//try to find begin mark.
	begin = data.find ("------ccr begin ", offset);

	//nothing possible found, die.
	if (begin == data.npos) return 0;

	//try to parse the begin mark
	std::string type, mark;

	//TODO parse it lol
	//TODO move offset

	//read all sections
	for (;;) {

	}

	//return the modified offset
	return offset;
}
