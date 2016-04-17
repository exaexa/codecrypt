
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

#ifndef _ccr_hash_h_
#define _ccr_hash_h_

#include <vector>
#include <string>
#include <map>
#include "types.h"
#include "factoryof.h"

/*
 * hash-providing functor class, meant to be instantiated by user.
 */
class hash_func
{
public:
	virtual std::vector<byte> operator() (const std::vector<byte>&) = 0;
	virtual uint size() = 0; //in bytes
};

class hash_proc
{
public:
	virtual uint size() = 0;
	virtual void init() = 0;

	virtual void eat (const byte*begin, const byte*end) = 0;
	virtual std::vector<byte> finish() = 0;
	virtual ~hash_proc() {}

	void eat (const std::vector<byte>&a) {
		return eat (& (a[0]), & (a[a.size()]));
	}

	typedef std::map<std::string, factoryof<hash_proc>*> suite_t;
	static suite_t& suite();
};

#endif

