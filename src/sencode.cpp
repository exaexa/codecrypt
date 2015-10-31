
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
#include <list>

#define sencode_max_int_len 9
#define sencode_max_int 999999999

static void parse_int (const std::string&str, int&pos, int len,
                       unsigned int&res)
{
	int length;

	res = 0;
	++pos; //skip 'i'
	if (pos >= len) goto fail;

	/*
	 * Strip special cases: Don't support the "empty zero" in form of 'ie'.
	 * Also, only purpose for having a leading zero in integers is to have
	 * actual 'i0e' zero. Other cases are disallowed because serialization
	 * would not be bijective otherwise.
	 */
	if (str[pos] == 'e') goto fail;
	if (str[pos] == '0') {
		++pos;
		if (pos < len && str[pos] == 'e') {
			res = 0;
			return;
		} else goto fail;
	}

	//parse the number, keep eye on maximum length
	length = 0;
	for (;;) {
		if (pos >= len) goto fail; //not terminated
		else if (str[pos] == 'e') break; //done good
		else if ( (str[pos] >= '0') and (str[pos] <= '9'))  //integer
			res = (10 * res) + (unsigned int) (str[pos] - '0');
		else goto fail; //something weird!
		++pos;
		if (++length > sencode_max_int_len) goto fail;
	}

	return;
fail:
	pos = -1;
}

static void parse_string (const std::string&str, int&pos, int len,
                          std::string&res)
{
	int bytes, length;

	/*
	 * First, read the amount of bytes.
	 * We need to keep this bijective, therefore avoid parsing of any
	 * incorrect cases with leading zeroes except for a single zero. Such
	 * cases can be distinguished very simply by having zero at first
	 * position and not having colon right after.
	 */

	bytes = 0;
	if (pos >= len) goto fail;
	if (str[pos] == '0') {
		++pos;
		if (pos < len && str[pos] == ':') {
			bytes = 0;
			return;
		} else goto bytes_done;
	}

	//parse the number.
	length = 0;
	for (;;) {
		if (pos >= len) goto fail;
		else if (str[pos] == ':') break; //got it
		else if ( (str[pos] >= '0') and (str[pos] <= '9'))  //integer
			bytes = (10 * bytes) + (int) (str[pos] - '0');
		else goto fail; //weird!
		++pos;
		if (++length > sencode_max_int_len) goto fail;
	}

bytes_done:

	++pos;
	if (pos + bytes >= len) goto fail;
	res = str.substr (pos, bytes);
	pos += bytes;
	--pos; //set position to last char of the bytestring (not behind it)
	return;
fail:
	pos = -1;
}

sencode* sencode_decode (const std::string& str)
{
	std::list<sencode*> stk;
	int pos = 0;
	int len = str.length();

	for (; pos < len; ++pos) {

		/* try to get a token */
		if (str[pos] == 's') {
			//push a new s-exp and don't allow closing it yet.
			stk.push_back (new sencode_list);
			continue;
		} else if (str[pos] == 'e') {
			//push nothing (so the TOS s-exp gets terminated)
		} else if (str[pos] == 'i') {
			//parse an integer (it's unsigned!)
			unsigned int res;
			parse_int (str, pos, len, res);
			if (pos < 0) break;
			stk.push_back (new sencode_int (res));

		} else if ( (str[pos] >= '0') && (str[pos] <= '9')) {
			//parse a bytestring
			std::string res;
			parse_string (str, pos, len, res);
			if (pos < 0) break;
			stk.push_back (new sencode_bytes (res));
		}

		/* if there's nothing on the stack now, it's an error. */
		if (stk.empty()) break;

		/* reduce stack. (return positively if it would
		 * get empty and there's nothing more to parse.) */
		if (stk.size() > 1) {
			std::list<sencode*>::iterator i = stk.end();
			--i;
			sencode*tos = *i;
			--i;
			sencode_list*se = dynamic_cast<sencode_list*> (*i);
			if (!se) break; //shouldn't happen, but keep eyes open!
			se->items.push_back (tos);
			stk.pop_back();
		} else if (pos + 1 == len) {
			return stk.front();
		}
	}

	/* error handling. Destroy the stack, return false. */

	for (std::list<sencode*>::iterator i = stk.begin(), e = stk.end();
	     i != e; ++i)
		sencode_destroy (*i);

	return NULL;
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
	if (i > sencode_max_int) return "i0e"; //failure fallback
	std::stringstream ss;
	ss << 'i' << i << 'e';
	return ss.str();
}

std::string sencode_bytes::encode()
{
	if (b.length() > sencode_max_int) return "0:"; //failure fallback
	std::stringstream ss;
	ss << b.length() << ':' << b;
	return ss.str();
}

