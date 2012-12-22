
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

#include "codecrypt.h"
#include "arcfour.h"

#include <stdlib.h>
#include <time.h>

#include <iostream>
#include <iomanip>
using namespace std;

class primitiverng : public prng
{
public:
	uint random (uint n) {
		return rand() % n;
	}

	void seed (uint n) {
		srand (time (NULL) + n);
	}
};

int main()
{
	arcfour<unsigned short> c;
	if (!c.init (10) ) {
		cout << "haha." << endl;
		return 1;
	}
	std::vector<unsigned short> k;
	k.push_back ('K');
	k.push_back ('e');
	k.push_back ('y');
	k.push_back ('l');
	k.push_back ('o');
	k.push_back ('l');
	c.load_key (k);

	for (int i = 0; i < 20; ++i)
		cout << hex << (int) c.gen() << endl;

	return 0;

#if 0
	primitiverng r;
	r.seed (0);

	mce::pubkey pub, pub2;
	mce::privkey priv, priv2;
	mce::generate (pub, priv, r, 6, 2);

	sencode *s;
	std::cout << priv.Pinv;
	s = priv.serialize();
	std::cout << s->encode();
	if (priv.unserialize (s) )
		std::cout << priv.Pinv;

	sencode_destroy (s);
	return 0;
	sencode_list*x = new sencode_list;
	x->items.push_back (new sencode_int (1) );
	x->items.push_back (new sencode_bytes ("ahoj") );
	std::string tmp = x->encode();
	std::cout << tmp << std::endl;
	sencode_destroy (x);
	sencode*s;
	sencode_decode (tmp, &s);
	std::cout << s->encode() << std::endl;
	sencode_destroy (s);
	bvector b;
	b.resize (9);
	b[0] = 1;
	b[5] = 1;
	b[8] = 1;
	s = b.serialize();
	b[6] = 1;
	std::cout << s->encode() << std::endl;
	if (b.unserialize (s) ) {
		std::cout << b ;
	}
	sencode_destroy (s);
	return 0;
	/* this is just a test, don't mind it */
	primitiverng r;
	r.seed (0);

	/*
	mce::privkey priv;
	mce::pubkey pub;
	mce::generate(pub,priv,r,8,7);

	bvector a,b;

	a.resize(priv.hash_size(),0);

	a[0]=1;
	a[2]=1;
	a[4]=1;
	a[5]=1;
	a[6]=1;
	a[7]=1;
	a[10]=1;
	a[12]=1;
	a[16]=1;
	a[20]=1;
	a[22]=1;
	a[24]=1;
	a[25]=1;
	a[26]=1;
	a[27]=1;
	a[110]=1;
	a[112]=1;
	a[116]=1;
	priv.prepare();
	priv.sign(a,b,3,10000,r);
	std::cout << a << b << pub.verify(b,a,3) << std::endl;
	*/
	cfs_qd::privkey priv;
	cfs_qd::pubkey pub;
	cfs_qd::generate (pub, priv, r, 7, 3, 7, 1);

	cout << "hash size: " << priv.hash_size() << ' ' << pub.hash_size() << endl;
	cout << "signature size:  " << priv.signature_size() << ' ' << pub.signature_size() << endl;

	cout << "sig weight: " << priv.signature_weight() << ' ' << pub.signature_weight() << endl;

	priv.prepare();

	bvector hash;
	hash.resize (priv.hash_size(), 0);
	hash[0] = 1;
	hash[2] = 1;
	hash[4] = 1;
	hash[5] = 1;
	hash[6] = 1;
	hash[7] = 1;
	hash[10] = 1;
	hash[12] = 1;
	hash[16] = 1;
	hash[20] = 1;
	hash[22] = 1;
	hash[24] = 1;
	hash[25] = 1;
	hash[26] = 1;
	hash[27] = 1;
	hash[110] = 1;
	hash[112] = 1;
	hash[116] = 1;

	cout << "HASH " << endl;
	cout << hash;

	bvector sig;
	if (priv.sign (hash, sig, 3, 10000, r) ) {
		cout << "failed" << endl;
		return 0;
	}

	cout << "SIGNATURE " << sig;

	if (pub.verify (sig, hash, 3) )
		cout << "verify failed" << endl;
	else	cout << "verify okay" << endl;

#endif
#if 0
	bvector plain;
	plain.resize (pub.plain_size(), 0);
	plain[0] = 1;
	plain[1] = 1;
	plain[2] = 1;

	cout << "PLAINTEXT" << endl;
	cout << plain;

	bvector cipher;
	pub.encrypt (plain, cipher, r);

	cout << "CIPHERTEXT" << endl;
	cout << cipher;

	bvector decrypted;
	priv.decrypt (cipher, decrypted);

	cout << "DECRYPTED" << endl;
	cout << decrypted;

#endif
	return 0;
}

