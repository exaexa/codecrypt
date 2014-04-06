
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

#include "symkey.h"

#include "sc.h"
#include "hash.h"
#include "str_match.h"
#include "iohelpers.h"

#include <sstream>

bool symkey::is_valid()
{
	return blocksize >= 1024 &&
	       blocksize < 0x10000000 && //256M
	       !ciphers.empty() &&
	       !hashes.empty() &&
	       key.size() >= 32 && //not less than 256bits of key stuff
	       key.size() < 2048;
}

bool symkey::create (const std::string&in, prng&rng)
{
	//first, find cipher and hash names
	blocksize = 1024 * 1024;
	uint keysize = 32;
	std::stringstream ss (in);
	std::string tok;
	while (getline (ss, tok, ',') ) {
		tok = to_unicase (tok);
		if (tok == "SHORTBLOCK") blocksize = 1024;
		else if (tok == "LONGBLOCK") blocksize = 64 * 1024 * 1024;
		else if (tok == "LONGKEY") keysize = 256;
		else if (streamcipher::suite().count (tok) )
			ciphers.insert (tok);
		else if (hash_proc::suite().count (tok) )
			hashes.insert (tok);
		else {
			err ("symkey: unknown token: " << tok);
			return false;
		}
	}

	//increase keysize, if needed
	for (std::set<std::string>::iterator
	     i = ciphers.begin(), e = ciphers.end();
	     i != e; ++i) {

		instanceof<streamcipher> sc
		(streamcipher::suite() [*i]->get() );
		sc.collect();
		if (sc->key_size() > keysize) keysize = sc->key_size();
	}


	//fill the key
	key.resize (keysize);
	for (uint i = 0; i < keysize; ++i) key[i] = rng.random (256);

	if (!is_valid() ) {
		err ("symkey: failed to produce valid symmetric key");
		err ("symkey: check that at least one hash and cipher is used");
		return false;
	}

	return true;
}

typedef std::list<instanceof<streamcipher> > scs_t;
typedef std::list<instanceof<hash_proc> > hashes_t;

bool symkey::encrypt (std::istream&in, std::ostream&out, prng&rng)
{
	if (!is_valid() ) return false;

	/*
	 * structure of symmetrically encrypted file:
	 *
	 * - one-time key part, key.size() bytes
	 *  (repeat:
	 * - 4B blocksize little-endian
	 * - blocksize encrypted bytes
	 * - sum(hashes's size) blocksize marker+bytes of block hashes
	 *  )
	 * - 4B less than blocksize (may be zero!)
	 * - possibly incomplete last block (may be empty)
	 * - hashes of last blocksize+block
	 * - eof
	 */

	std::vector<byte> otkey;
	otkey.resize (key.size() );
	for (uint i = 0; i < otkey.size(); ++i) otkey[i] = rng.random (256);

	/*
	 * initialize the ciphers
	 */

	scs_t scs;
	for (std::set<std::string>::iterator
	     i = ciphers.begin(), e = ciphers.end();
	     i != e; ++i) {
		if (!streamcipher::suite().count (*i) ) {
			err ("symkey: unsupported cipher: " << *i);
			return false;
		}
		scs.push_back (streamcipher::suite() [*i]->get() );
		scs.back().collect();
		scs.back()->init();
		scs.back()->load_key_vector (key);
		scs.back()->load_key_vector (otkey);
	}

	/*
	 * initialize the hashes
	 */

	uint hashes_size = 0;

	hashes_t hs;
	for (std::set<std::string>::iterator
	     i = hashes.begin(), e = hashes.end();
	     i != e; ++i) {
		if (!hash_proc::suite().count (*i) ) {
			err ("symkey: unsupported hash function: " << *i);
			return false;
		}
		hs.push_back (hash_proc::suite() [*i]->get() );
		hs.back().collect();

		hashes_size += hs.back()->size();
	}

	/*
	 * output the onetime key
	 */

	out.write ( (char*) & (otkey[0]), otkey.size() );

	/*
	 * process the blocks
	 */

	std::vector<byte>buf, cipbuf;
	buf.resize (4 + blocksize + hashes_size);
	cipbuf.resize (buf.size() );

	for (;;) {
		in.read ( (char*) & (buf[4]), blocksize);
		uint bytes_read = in.gcount();

		if (!in && !in.eof() ) {
			err ("symkey: failed reading input");
			return false;
		}

		//now we got bytes_read of key stuff ready in buf.
		uint blksizeid = bytes_read;
		for (uint i = 0; i < 4; ++i) {
			buf[i] = blksizeid & 0xff;
			blksizeid >>= 8;
		}

		//hashup!
		uint hashpos = 4 + bytes_read;
		for (hashes_t::iterator i = hs.begin(), e = hs.end();
		     i != e; ++i) {
			hash_proc&hp = **i;
			hp.init();
			hp.eat (& (buf[0]), & (buf[4 + bytes_read]) );
			std::vector<byte> res = hp.finish();
			for (uint j = 0; j < res.size(); ++j, ++hashpos)
				buf[hashpos] = res[j];
		}

		//encrypt!
		for (scs_t::iterator i = scs.begin(), e = scs.end();
		     i != e; ++i) {
			streamcipher&sc = **i;
			sc.gen (hashpos, & (cipbuf[0]) );
			for (uint j = 0; j < hashpos; ++j)
				buf[j] = buf[j] ^ cipbuf[j];
		}

		//output!
		out.write ( (char*) & (buf[0]), hashpos);
		if (!out) {
			err ("symkey: failed to write output");
			return false;
		}

		//this was the last one
		if (bytes_read < blocksize) break;
	}

	return true;
}

int symkey::decrypt (std::istream&in, std::ostream&out)
{
	if (!is_valid() ) return 1;

	std::vector<byte> otkey;
	otkey.resize (key.size() );

	/*
	 * read otkey
	 */

	in.read ( (char*) & (otkey[0]), otkey.size() );
	if (in.gcount() != (std::streamsize) otkey.size() || !in) {
		err ("symkey: failed reading input");
		return 1;
	}

	/*
	 * initialize the ciphers
	 */

	scs_t scs;
	for (std::set<std::string>::iterator
	     i = ciphers.begin(), e = ciphers.end();
	     i != e; ++i) {
		if (!streamcipher::suite().count (*i) ) {
			err ("symkey: unsupported cipher: " << *i);
			return 1;
		}
		scs.push_back (streamcipher::suite() [*i]->get() );
		scs.back().collect();
		scs.back()->init();
		scs.back()->load_key_vector (key);
		scs.back()->load_key_vector (otkey);
	}

	/*
	 * initialize the hashes
	 */

	uint hashes_size = 0;

	hashes_t hs;
	for (std::set<std::string>::iterator
	     i = hashes.begin(), e = hashes.end();
	     i != e; ++i) {
		if (!hash_proc::suite().count (*i) ) {
			err ("symkey: unsupported hash function: " << *i);
			return 1;
		}
		hs.push_back (hash_proc::suite() [*i]->get() );
		hs.back().collect();

		hashes_size += hs.back()->size();
	}

	/*
	 * process the blocks
	 */

	std::vector<byte> buf, cipbuf;
	buf.resize (4 + blocksize + hashes_size);
	cipbuf.resize (buf.size() );

	for (;;) {
		in.read ( (char*) & (buf[0]), buf.size() );
		uint bytes_read = in.gcount();

		if ( (!in && !in.eof() ) || bytes_read < 4 + hashes_size) {
			err ("symkey: failed reading input");
			return 1;
		}

		//decrypt!
		for (scs_t::iterator i = scs.begin(), e = scs.end();
		     i != e; ++i) {
			streamcipher&sc = **i;
			sc.gen (bytes_read, & (cipbuf[0]) );
			for (uint j = 0; j < bytes_read; ++j)
				buf[j] = buf[j] ^ cipbuf[j];
		}

		//verify the size
		bytes_read -= (4 + hashes_size);

		uint blksizeid = bytes_read;
		for (uint i = 0; i < 4; ++i) {
			if (buf[i] != (blksizeid & 0xff) ) {
				err ("symkey: mangled input");
				return 3;
			}
			blksizeid >>= 8;
		}

		//verify the hashes
		uint hashpos = 4 + bytes_read;
		for (hashes_t::iterator i = hs.begin(), e = hs.end();
		     i != e; ++i) {
			hash_proc&hp = **i;
			hp.init();
			hp.eat (& (buf[0]), & (buf[4 + bytes_read]) );
			std::vector<byte> res = hp.finish();
			for (uint j = 0; j < res.size(); ++j, ++hashpos)
				if (buf[hashpos] != res[j]) {
					err ("symkey: mangled input");
					return 3;
				}
		}

		//now that all is OK, output!
		out.write ( (char*) & (buf[4]), bytes_read);

		//last one
		if (bytes_read < blocksize) break;
	}

	//did we read whole input?
	if (!in.eof() ) {
		err ("symkey: failed reading input");
		return 1;
	}
	return 0;
}
