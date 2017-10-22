
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

#ifndef _ccr_seclock_h_
#define _ccr_seclock_h_

#include <string>

#include "prng.h"
#include "symkey.h"

bool looks_like_locked_secret (const std::string&);
bool load_lock_secret (symkey&sk,
                       std::string withlock,
                       const std::string &reason,
                       const std::string &secret_type,
                       bool for_locking);
bool lock_secret (const std::string&secret, std::string&locked,
                  const std::string&withlock,
                  const std::string&reason,
                  const std::string&secret_type,
                  prng&rng);
bool unlock_secret (const std::string&locked, std::string&secret,
                    const std::string&withlock,
                    const std::string&reason,
                    const std::string&secret_type);

#endif
