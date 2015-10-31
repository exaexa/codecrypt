
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

#include "hash.h"

#include "str_match.h"

#include "sha_hash.h"
#include "rmd_hash.h"
#include "tiger_hash.h"
#include "cube_hash.h"

hash_proc::suite_t& hash_proc::suite()
{
	static suite_t s;

#define do_hash(name,type) \
	static factoryof<hash_proc,type> type##_var; \
	s[to_unicase(name)]=&type##_var;

	if (s.empty()) {
		do_hash ("CUBE512", cube512proc);
#if HAVE_CRYPTOPP==1
		do_hash ("RIPEMD128", rmd128proc);
		do_hash ("TIGER192", tiger192proc);
		do_hash ("SHA256", sha256proc);
		do_hash ("SHA512", sha512proc);
#endif
	}

	return s;
}
