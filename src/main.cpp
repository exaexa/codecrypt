
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

#include <stdlib.h>
#include <time.h>

#include <iostream>
using namespace std;

class primitiverng : public ccr::prng
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
	/* this is just a test, don't mind it */
	primitiverng r;
	r.seed (0);

	ccr::mce_qd::privkey priv;
	ccr::mce_qd::pubkey pub;
	ccr::mce_qd::generate (pub, priv, r, 11, 5, 2);

	cout << "cipher size: " << priv.cipher_size() << ' ' << pub.cipher_size() << endl;
	cout << "plain size:  " << priv.plain_size() << ' ' << pub.plain_size() << endl;

	priv.prepare();

	ccr::bvector plain;
	plain.resize (pub.plain_size(), 0);
	plain[0] = 1;
	plain[1] = 1;
	plain[2] = 1;

	cout << "PLAINTEXT" << endl;
	cout << plain;

	ccr::bvector cipher;
	pub.encrypt (plain, cipher, r);

	cout << "CIPHERTEXT" << endl;
	cout << cipher;

	ccr::bvector decrypted;
	priv.decrypt (cipher, decrypted);

	cout << "DECRYPTED" << endl;
	cout << decrypted;

	return 0;
}

