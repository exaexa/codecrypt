
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2016 Mirek Kratochvil <exa.exa@gmail.com>
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

#include "cubehash_impl.h"

#include "hash.h"

template<int I, int R, int B, int F, int H>
class cubehash : public hash_func
{
public:
	uint size() {
		return H;
	}

	std::vector<byte> operator() (const std::vector<byte>&a) {
		cubehash_state<I, R, B, F, H> state;
		size_t i;

		state.init();

		for (i = 0; i + B <= a.size(); i += B)
			state.process_block (& (a[i]));

		state.process_final_incomplete_block (& (a[i]), a.size() - i);
		std::vector<byte> result;
		result.resize (H, 0);
		state.get_hash (& (result[0]));
		return result;
	}
};

template<int I, int R, int B, int F, int H>
class cubehashproc : public hash_proc
{
	cubehash_state<I, R, B, F, H> state;
	byte buf[B];
	int bpos;
public:
	uint size() {
		return H;
	}

	void init() {
		state.init();
		bpos = 0;
	}

	void eat (const byte*a, const byte*aend) {
		int apos = 0;
		int asize = aend - a;
		if (bpos) {
			for (; bpos < B && apos < asize; ++bpos, ++apos)
				buf[bpos] = a[apos];
			if (bpos == B) {
				state.process_block (buf);
				bpos = 0;
			}
		}
		while (apos + B <= asize) {
			state.process_block (& (a[apos]));
			apos += B;
		}
		for (; apos < asize; ++apos, ++bpos)
			buf[bpos] = a[apos];
	}

	std::vector<byte> finish() {
		state.process_final_incomplete_block (buf, bpos);
		std::vector<byte> result;
		result.resize (H, 0);
		state.get_hash (& (result[0]));
		return result;
	}
};



class cube128hash : public cubehash<16, 16, 32, 32, 16> {};
class cube192hash : public cubehash<16, 16, 32, 32, 24> {};
class cube256hash : public cubehash<16, 16, 32, 32, 32> {};
class cube384hash : public cubehash<16, 16, 32, 32, 48> {};
class cube512hash : public cubehash<16, 16, 32, 32, 64> {};

class cube128proc : public cubehashproc<16, 16, 32, 32, 16> {};
class cube192proc : public cubehashproc<16, 16, 32, 32, 24> {};
class cube256proc : public cubehashproc<16, 16, 32, 32, 32> {};
class cube384proc : public cubehashproc<16, 16, 32, 32, 48> {};
class cube512proc : public cubehashproc<16, 16, 32, 32, 64> {};
