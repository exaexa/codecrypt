
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

#ifndef _ccr_sha_hash_h_
#define _ccr_sha_hash_h_

#if HAVE_CRYPTOPP==1

#include "hash.h"

#include <crypto++/sha.h>

template <class shatype>
class shahash : public hash_func
{
public:
	uint size() {
		return shatype::DIGESTSIZE;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		std::vector<byte> r;
		r.resize (size());
		shatype().CalculateDigest (& (r[0]),
		                           & (a[0]),
		                           a.size());
		return r;
	}
};

class sha256hash : public shahash<CryptoPP::SHA256> {};
class sha384hash : public shahash<CryptoPP::SHA384> {};
class sha512hash : public shahash<CryptoPP::SHA512> {};

template <class shatype>
class shaproc : public hash_proc
{
	shatype state;
public:
	uint size() {
		return shatype::DIGESTSIZE;
	}

	void init() {
		state.Restart();
	}

	void eat (const byte*a, const byte*aend) {
		state.Update (a, aend - a);
	}

	std::vector<byte> finish() {
		std::vector<byte> r;
		r.resize (size());
		state.Final (& (r[0]));
		return r;
	}
};

class sha256proc : public shaproc<CryptoPP::SHA256> {};
class sha384proc : public shaproc<CryptoPP::SHA384> {};
class sha512proc : public shaproc<CryptoPP::SHA512> {};

#endif //HAVE_CRYPTOPP==1

#endif
