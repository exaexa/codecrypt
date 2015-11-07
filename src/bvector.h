
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

#ifndef _ccr_bvector_h_
#define _ccr_bvector_h_

#include <vector>
#include <string>

#include <stdint.h>

#include "types.h"
#include "sencode.h"
#include "vector_item.h"

/*
 * vector over GF(2), in some cases usuable also as a polynomial over GF(2).
 *
 * Blocks of 64bit integers for kinda-efficiency.
 */

class polynomial;
class gf2m;
class bvector
{
public:
	/*
	 * types
	 */

	struct const_reference {
		const bvector&bv;
		size_t offset;

		const_reference (const bvector&BV, size_t O) : bv (BV), offset (O) {}

		inline operator bool() const {
			return bv.get (offset);
		}
	};

	struct reference {
		bvector&bv;
		size_t offset;

		reference (bvector&BV, size_t O) : bv (BV), offset (O) {}

		inline operator bool() const {
			return bv.get (offset);
		}

		inline reference& operator= (const reference&a) {
			bv.set (offset, (bool) a);
			return *this;
		}

		inline reference& operator= (bool val) {
			bv.set (offset, val);
			return *this;
		}
	};

	typedef size_t size_type;

private:
	/*
	 * invariants:
	 * unused data are filled with zeros
	 * _data.size() == datasize(_size)
	 */

	std::vector<uint64_t> _data;
	size_t _size;

	static inline size_t blockof (size_t s) {
		return s >> 6;
	}

	static inline size_t blockpos (size_t s) {
		return s & 0x3f;
	}

	static inline size_t datasize (size_t s) {
		if (s & 0x3f) return 1 + (s >> 6);
		return s >> 6;
	}

	void fix_padding();

protected:
	_ccr_declare_vector_item
public:
	bvector() {
		_size = 0;
	}

	bvector (const bvector&a) : _data (a._data) {
		_size = a._size;
	}

	inline size_t size() const {
		return _size;
	}

	inline void clear() {
		_size = 0;
		_data.clear();
	}

	inline void swap (bvector&a) {
		size_t s = _size;
		_size = a._size;
		a._size = s;

		_data.swap (a._data);
	}

	void resize (size_t size, bool def = false);

	inline void reserve (size_t size) {
		_data.reserve (datasize (size));
	}

	inline void fill_ones (size_t from = 0) {
		fill_ones (from, _size);
	}

	void fill_ones (size_t from, size_t to);

	inline void fill_zeros (size_t from = 0) {
		fill_zeros (from, _size);
	}

	void fill_zeros (size_t from, size_t to);

	inline bool get (size_t i) const {
		return (_data[blockof (i)] >> blockpos (i)) & 1;
	}

	inline void set (size_t i, bool val) {
		if (val) set (i);
		else unset (i);
	}

	inline void set (size_t i) {
		_data[blockof (i)] |= ( (uint64_t) 1) << blockpos (i);
	}

	inline void unset (size_t i) {
		_data[blockof (i)] &= ~ ( ( (uint64_t) 1) << blockpos (i));
	}

	inline const_reference operator[] (size_t pos) const {
		return const_reference (*this, pos);
	}

	inline reference operator[] (size_t pos) {
		return reference (*this, pos);
	}

	uint hamming_weight();
	void append (const bvector&);
	void add (const bvector&);
	void add_offset (const bvector&, size_t offset_from, size_t offset_to, size_t cnt = 0);

	void add_offset (const bvector&, size_t offset_to);
	void add_range (const bvector&, size_t, size_t);
	void rot_add (const bvector&, size_t);
	void set_block (const bvector&, size_t);
	void get_block (size_t, size_t, bvector&) const;
	uint and_hamming_weight (const bvector&) const;

	inline bool operator* (const bvector&a) const {
		//dot product
		return and_hamming_weight (a) & 1;
	}

	bool zero() const;

	void from_poly_cotrace (const polynomial&, gf2m&);

	void colex_rank (bvector&) const;
	bool colex_unrank (bvector&, uint n, uint k) const;

	void to_string (std::string&) const;
	void to_bytes (std::vector<byte>&) const;

	bool to_string_check (std::string&s) const {
		if (size() & 7) return false;
		to_string (s);
		return true;
	}

	void from_string (const std::string&, size_t bits = 0);
	void from_bytes (const std::vector<byte>&, size_t bits = 0);

	sencode* serialize();
	bool unserialize (sencode*);
};

#endif
