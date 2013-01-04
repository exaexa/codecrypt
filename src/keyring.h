
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

#ifndef _ccr_keys_h_
#define _ccr_keys_h_

#include <string>

#include "sencode.h"

class keyring
{
public:
	bool disk_sync();

	sencode* get_pubkey (const std::string&key_id);
	void remove_pubkey (const std::string&key_id);
	bool store_pubkey (const std::string&key_id, sencode*);

	sencode* get_privkey (const std::string&key_id);
	void remove_privkey (const std::string&key_id);
	bool store_privkey (const std::string&key_id, sencode*);
};

#endif

