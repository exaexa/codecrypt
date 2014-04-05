
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

#include "sc.h"

#include "arcfour.h"
#include "xsynd.h"
#include "chacha.h"

typedef arcfour<> arcfour_t; //template god demands sacrifice

streamcipher::suite_t& streamcipher::suite()
{
	static suite_t s;
#define do_cipher(name,type) \
	static factoryof<streamcipher,type> type##_var; \
	s[name]=&type##_var;

	if (s.empty() ) {
		do_cipher ("ARCFOUR", arcfour_t);
		do_cipher ("CHACHA20", chacha20);
		do_cipher ("XSYND", xsynd);
	}

	return s;
}
