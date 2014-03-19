
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

#ifndef _ccr_sc_h_
#define _ccr_sc_h_

#include "types.h"

#include <sys/types.h>

class streamcipher
{
public:
	virtual bool init() = 0;
	virtual void clear() = 0;
	virtual void load_key (const byte*begin, const byte*end) = 0;
	virtual byte gen() = 0;
	virtual void gen (size_t n, byte*out) = 0;
	virtual size_t block_size() = 0;

	void discard (size_t n) {
		gen (n, 0);
	}
};

#endif