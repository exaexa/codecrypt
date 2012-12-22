
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

#ifndef _ccr_hash_h_
#define _ccr_hash_h_

/*
 * hash function templates
 *
 * usuable mostly for injection into actual code
 */

class hash {
public:
	hash();
	virtual ~hash()=0;

	virtual void init()=0;
	virtual void update(const char*a, size_t len)=0;
	virtual size_t size()=0;
	virtual void final(const char*a)=0;
};

class hash_factory {
public:
	hash* create();
	void free(hash*);
};

#endif

