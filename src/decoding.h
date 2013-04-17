
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

#ifndef _ccr_decoding_h_
#define _ccr_decoding_h_

#include <vector>
#include "polynomial.h"
#include "gf2m.h"
#include "bvector.h"

void compute_goppa_error_locator (polynomial&syndrome,
                                  gf2m&fld,
                                  polynomial&goppa,
                                  std::vector<polynomial>& sqInv,
                                  polynomial&loc);

void compute_alternant_error_locator (polynomial&syndrome,
                                      gf2m&fld,
                                      uint tt,
                                      polynomial&loc);

bool evaluate_error_locator_dumb (polynomial&el, bvector&ev, gf2m&fld);
bool evaluate_error_locator_trace (polynomial&el, bvector&ev, gf2m&fld);

#endif
