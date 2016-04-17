
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

#include "envelope.h"

/*
 * helpers
 */

inline static bool acceptable_char (char c)
{
	return
	    (c >= 'a' && c <= 'z') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= '0' && c <= '9') ||
	    c == '_' || c == '.';
}

static bool acceptable_id (const std::string&a)
{
	if (!a.length()) return false;
	for (size_t i = 0; i < a.length(); ++i)
		if (!acceptable_char (a[i])) return false;
	return true;
}

/*
 * how do the ascii envelopes look like?
 *
 * similarly to PGP:
 *
 * ------ccr begin typeident termident------
 * data
 * ------ccr cut typeident termident------
 * next part data
 * ------ccr cut typeident termident------
 * other next part data
 * ------ccr end typeident termident------
 *
 * To distinguish ourselves from PGP, we use six dashes and prefixed CCR name.
 * No version information is supplied - versioning should be contained
 * preferably in typeident, e.g. like "message" "better_message" and
 * "bettermessage_version3.5".
 *
 * Cleartext two-part messages and similar evil sorceries are generalized to
 * multipart messages using the "part cut".
 *
 * Also, to prevent cleartext embedding conflicts, we add termident, which is
 * basically a random string of letters and numbers that serves as a mark that
 * must be the same on the begin and end.
 *
 * Also also, there's always newline before cut/end, even if there already is a
 * newline from previous cut. Therefore, size 0 section looks like it has an
 * empty line inside.
 */

size_t envelope_read (const std::string&data, size_t offset,
                      std::string&out_type,
                      std::vector<std::string>&out_parts)
{
	for (;;) {
		//try to find begin mark.
		std::string
		begin_prefix = "------ccr begin ",
		begin_suffix = "------\n";
		size_t begin = data.find (begin_prefix, offset);

		//nothing possible found, die.
		if (begin == data.npos) return 0;

		//verify it's on the beginning of the line
		if (begin > 0) if (data[begin - 1] != '\n') {
				offset += begin_prefix.length();
				continue;
			}

		//try to parse the typeident and termident
		std::string type, term;
		offset = begin + begin_prefix.length();

		//find and verify possible positions of type and term strings
		size_t eoterm, eotype;

		eotype = data.find (' ', offset);
		if (eotype == data.npos) continue;

		eoterm = data.find (begin_suffix, eotype + 1);

		if (eoterm == data.npos) continue;

		type = data.substr (offset, eotype - offset);
		term = data.substr (eotype + 1, eoterm - eotype - 1);

		//verify that type&term are only of acceptable characters
		if (!acceptable_id (type) || !acceptable_id (term))
			continue;

		offset = eoterm + begin_suffix.length();

		//read all sections
		std::string
		cut_sep = "\n------ccr cut " + type + " " + term + "------\n",
		end_sep = "\n------ccr end " + type + " " + term + "------\n";

		out_parts.clear();

		bool retry = false;
		for (;;) {
			//find closest cut or sep
			size_t cut_pos = data.find (cut_sep, offset),
			       end_pos = data.find (end_sep, offset);

			if (end_pos == data.npos) {
				//can't even find end, don't care about cut_pos
				retry = true;
				break;
			}

			if (cut_pos != data.npos && cut_pos < end_pos) {
				//there is cut
				out_parts.push_back
				(data.substr (offset, cut_pos - offset));
			} else {
				//no cut, it's till the end
				out_parts.push_back
				(data.substr (offset, end_pos - offset));
			}

			if (cut_pos == data.npos) {
				//it was end_pos, finished!
				offset = end_pos + end_sep.length();
				break;
			} else {
				//move offset for next search
				offset = cut_pos + cut_sep.length();
			}
		}

		if (retry) continue;

		//return type and modified offset
		out_type = type;
		return offset;
	}
}

/*
 * The Much Simpler Envelope Formatter!
 */

static void gen_random_term (std::string&out, prng&rng, size_t length)
{
	//this could be longer, but don't generate absolute mess.
	static const char letters[] = "abcdefghijklmnopqrstuvwxyz0123456789";

	out.resize (length);
	for (size_t i = 0; i < length; ++i) {
		out[i] = letters[rng.random (36)];
	}
}

std::string envelope_format (const std::string&type,
                             const std::vector<std::string>& parts,
                             prng&rng)
{

	for (;;) {
		std::string term;
		gen_random_term (term, rng, 16);

		std::string
		cut_sep = "\n------ccr cut " + type + " " + term + "------\n",
		end_sep = "\n------ccr end " + type + " " + term + "------\n";

		//check whether there's no collision with boundary
		bool good = true;
		std::vector<std::string>::const_iterator i, e;
		for (i = parts.begin(), e = parts.end(); i != e; ++i) {
			if (i->find (cut_sep) != i->npos ||
			    i->find (end_sep) != i->npos) {
				good = false;
				break;
			}
		}
		if (!good) continue; //retry generating the termident mark

		//now construct the result
		std::string
		res = "------ccr begin " + type + " " + term + "------\n";

		if (parts.size() > 0) {
			res += parts[0];
			for (i = parts.begin() + 1, e = parts.end();
			     i != e; ++i) {
				res += cut_sep;
				res += *i;
			}
		}
		res += end_sep;

		return res;
	}
}

bool envelope_lookalike (const std::string&data)
{
	return data.find ("------ccr begin ") != data.npos;
}
