
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

#ifndef _ccr_factoryof_h_
#define _ccr_factoryof_h_

/*
 * This is a generic tool for safe spawning of instances of various derived
 * ciphers on the fly.
 */

template<class base_type>
class instanceof
{
	base_type*ptr;
	bool deletable;
public:
	base_type& operator*() {
		return *ptr;
	}
	const base_type& operator*() const {
		return *ptr;
	}

	base_type* operator->() {
		return ptr;
	}
	const base_type* operator->() const {
		return ptr;
	}

	instanceof (base_type*p) : ptr (p), deletable (false) {}
	instanceof (const instanceof&x) : ptr (x.ptr), deletable (false) {}
	instanceof () {
		deletable = false;
		ptr = 0;
	}

	void collect() {
		deletable = true;
	}
	void forget() {
		deletable = false;
	}

	~instanceof() {
		if (deletable) delete ptr;
	}
};

template<class base_type, class derived_type = base_type> class factoryof;

template<class base_type, class derived_type>
class factoryof : public factoryof<base_type, base_type>
{
public:
	base_type* get() {
		return new derived_type;
	}
};

template<class base_type>
class factoryof<base_type, base_type>
{
public:
	virtual base_type* get() = 0;
};

#endif
