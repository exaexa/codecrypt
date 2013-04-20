
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

#include "actions.h"

int action_gen_key (const std::string& algspec, const std::string&name,
                    keyring&, algorithm_suite&)
{
	return 0;
}

/*
 * signatures/encryptions
 */

int action_encrypt (const std::string&recipient, bool armor,
                    keyring&, algorithm_suite&)
{
	return 0;
}


int action_decrypt (bool armor,
                    keyring&, algorithm_suite&)
{
	return 0;
}


int action_sign (const std::string&user, bool armor, const std::string&detach,
                 keyring&, algorithm_suite&)
{
	return 0;
}


int action_verify (bool armor, const std::string&detach,
                   keyring&, algorithm_suite&)
{
	return 0;
}


int action_sign_encrypt (const std::string&user, const std::string&recipient,
                         bool armor, keyring&, algorithm_suite&)
{
	return 0;
}


int action_decrypt_verify (bool armor, keyring&, algorithm_suite&)
{
	return 0;
}


/*
 * keyring stuff
 */

int action_list (bool nice_fingerprint, const std::string&filter,
                 keyring&)
{
	return 0;
}


int action_import (bool armor, bool no_action, bool yes,
                   const std::string&filter, const std::string&name,
                   keyring&)
{
	return 0;
}


int action_export (bool armor,
                   const std::string&filter, const std::string&name,
                   keyring&)
{
	return 0;
}


int action_delete (bool yes, const std::string&filter, keyring&)
{
	return 0;
}


int action_rename (bool yes,
                   const std::string&filter, const std::string&name,
                   keyring&)
{
	return 0;
}



int action_list_sec (bool nice_fingerprint, const std::string&filter,
                     keyring&)
{
	return 0;
}


int action_import_sec (bool armor, bool no_action, bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&)
{
	return 0;
}


int action_export_sec (bool armor,
                       const std::string&filter, const std::string&name,
                       keyring&)
{
	return 0;
}


int action_delete_sec (bool yes, const std::string&filter, keyring&)
{
	return 0;
}


int action_rename_sec (bool yes,
                       const std::string&filter, const std::string&name,
                       keyring&)
{
	return 0;
}
