
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

#include "privfile.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

bool put_private_file (const std::string&fn,
                       const std::string&contents, bool force_perms)
{
	struct stat st;
	if (stat (fn.c_str(), &st)) {
		if (errno != ENOENT)
			return false;

		//if it simply doesn't exist, create it
		int fd;
		fd = creat (fn.c_str(), S_IRUSR | S_IWUSR);
		if (fd < 0) return false;
		ssize_t res = write (fd, contents.c_str(),
		                     contents.length());
		if (close (fd)) return false;
		if ( (size_t) res != contents.length()) return false;

	} else {
		if (!S_ISREG (st.st_mode))
			return false;

		//remove others' read/write. group r/w is untouched.
		if (force_perms && (st.st_mode & 07)) {
			if (chmod (fn.c_str(), st.st_mode & ~07))
				return false;
		}
	}

	if (access (fn.c_str(), R_OK | W_OK)) return false;

	return true;
}
