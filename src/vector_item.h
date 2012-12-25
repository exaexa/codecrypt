
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

#ifndef _vector_item_h_
#define _vector_item_h_

//little STL helper, because writing (*this)[i] everywhere is clumsy
#define _ccr_declare_vector_item \
	inline reference item(size_type n) \
		{ return (*this)[n]; }; \
	inline const_reference item(size_type n) const \
		{ return (*this)[n]; };
#define _ccr_declare_matrix_item \
	inline value_type::reference \
		item(size_type n, size_type m) \
		{ return (*this)[n][m]; }; \
	inline value_type::const_reference \
		item(size_type n, size_type m) const \
		{ return (*this)[n][m]; };

#endif

