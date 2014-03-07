
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

#ifndef _ccr_actions_h_
#define _ccr_actions_h_

/*
 * actions = stuff the user can do. main() calls this accordingly to options
 */
#include <string>
#include "keyring.h"
#include "algorithm.h"

int action_gen_key (const std::string& algspec, const std::string&name,
                    keyring&, algorithm_suite&);

/*
 * signatures/encryptions
 */

int action_encrypt (const std::string&recipient, bool armor,
                    keyring&, algorithm_suite&);

int action_decrypt (bool armor,
                    keyring&, algorithm_suite&);

int action_sign (const std::string&user, bool armor, const std::string&detach,
                 bool clearsign, const std::string&symmetric,
                 keyring&, algorithm_suite&);

int action_verify (bool armor, const std::string&detach,
                   bool clearsign, bool yes, const std::string&symmetric,
                   keyring&, algorithm_suite&);

int action_sign_encrypt (const std::string&user, const std::string&recipient,
                         bool armor, keyring&, algorithm_suite&);

int action_decrypt_verify (bool armor, bool yes,
                           keyring&, algorithm_suite&);

/*
 * keyring stuff
 */

int action_list (bool nice_fingerprint, const std::string&filter,
                 keyring&);

int action_import (bool armor, bool no_action, bool yes, bool fp,
                   const std::string&filter, const std::string&name,
                   keyring&);

int action_export (bool armor,
                   const std::string&filter, const std::string&name,
                   keyring&);

int action_delete (bool yes, const std::string&filter, keyring&);

int action_rename (bool yes,
                   const std::string&filter, const std::string&name,
                   keyring&);


int action_list_sec (bool nice_fingerprint, const std::string&filter,
                     keyring&);

int action_import_sec (bool armor, bool no_action, bool yes, bool fp,
                       const std::string&filter, const std::string&name,
                       keyring&);

int action_export_sec (bool armor, bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&);

int action_delete_sec (bool yes, const std::string&filter, keyring&);

int action_rename_sec (bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&);


#endif
