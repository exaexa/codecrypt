
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

#include "hashfile.h"

#include <map>
using namespace std;

#include "sha_hash.h"
#include "tiger_hash.h"
#include "cube_hash.h"

#include "iohelpers.h"

/*
 * helper -- size measurement is a hash as well
 */

class size64hash : public hash_func
{
	uint size() {
		return 8;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		uint64_t s = a.size();
		std::vector<byte> r;
		r.resize (8, 0);
		for (int i = 0; i < 8; ++i) {
			r[i] = s & 0xff;
			s >>= 8;
		}
		return r;
	}
};

/*
 * list of hash functions availabel
 */

typedef map<string, hash_func*> hashmap;

void fill_hashmap (hashmap&t)
{
#if HAVE_CRYPTOPP==1
	static tiger192hash th;
	t["TIGER192"] = &th;
	static sha256hash sh256;
	t["SHA256"] = &sh256;
	static sha512hash sh512;
	t["SHA512"] = &sh512;
#endif //HAVE_CRYPTOPP
	static cube512hash c512;
	t["CUBE512"] = &c512;
	static size64hash s;
	t["SIZE64"] = &s;
}

bool hashfile::create (istream&in)
{
	hashes.clear();

	/* TODO this should use streams, rewrite it. */

	std::vector<byte> data;
	if (!read_all_input (data, in) )
		return false;

	hashmap hm;
	fill_hashmap (hm);

	for (hashmap::iterator i = hm.begin(), e = hm.end(); i != e; ++i)
		hashes[i->first] = (*i->second) (data);

	return true;
}

int hashfile::verify (istream&in)
{
	std::vector<byte> data;
	if (!read_all_input (data, in) ) return 1;

	hashmap hm;
	fill_hashmap (hm);

	bool matched_one_hash = false;
	for (hashmap::iterator i = hm.begin(), e = hm.end(); i != e; ++i) {

		if (!hashes.count (i->first) ) continue;

		if (hashes[i->first] != (*i->second) (data) )
			return 3; //verification failed

		matched_one_hash = true;
	}

	if (matched_one_hash) return 0; //all OK
	else return 2; //more data needed.
}
