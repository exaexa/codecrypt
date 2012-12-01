
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

#include "sencode.h"
#include <sstream>

bool sencode_decode (const std::string& str, sencode**out)
{

	return false;
}

void sencode_destroy (sencode*x)
{
	x->destroy();
	delete x;
}

void sencode_list::destroy()
{
	for (std::vector<sencode*>::iterator
	     i = items.begin(),
	     e = items.end();
	     i != e; ++i)
		sencode_destroy (*i);

	items.clear();
}

std::string sencode_list::encode()
{
	std::string r = "s";
	for (std::vector<sencode*>::iterator
	     i = items.begin(),
	     e = items.end();
	     i != e; ++i)
		r += (*i)->encode();

	r += "e";
	return r;
}

std::string sencode_int::encode()
{
	std::string r;
	std::stringstream ss (r);
	ss << 'i' << i << 'e';
	return r;
}

std::string sencode_bytes::encode()
{
	std::string r;
	std::stringstream ss (r);
	ss << b.length() << ':' << b;
	return r;
}

