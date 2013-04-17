
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

#ifndef _ccr_envelope_h_
#define _ccr_envelope_h_

#include <string>
#include <vector>

/*
 * Tools for finding envelopes in ascii/utf-8 text.
 *
 * We simply don't care about wide chars in text, UTF-16+, nor conflicting
 * encodings, nor any similar abominations.
 *
 * envelope_get tries to find an envelope in text data, starting from offset,
 * returning the offset of first possible following envelope or 0 if nothing
 * usuable was found.
 */

size_t envelope_get (const std::string& data, size_t offset,
                     std::string&out_type,
                     std::vector<std::string>&out_parts);

#endif

