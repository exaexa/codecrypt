
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
	primitiverng r;
	r.seed (0);

	ccr::mce::privkey priv;
	ccr::mce::pubkey pub;
	ccr::mce::generate (pub, priv, r, 7, 4);

	cout << "PRIVATE KEY" << endl;
	cout << priv.fld;
	cout << priv.hperm;
	cout << priv.Pinv;
	cout << priv.Sinv;
	cout << priv.g;
	cout << "PUBLIC KEY" << endl;
	cout << pub.t << endl;
	cout << pub.G;

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

	priv.prepare();

	ccr::bvector result;
	priv.decrypt (cipher, result);

	cout << "DECRYPTED" << endl;
	cout << result;

	/* signature test */

	ccr::bvector hash, signature;

	hash.resize (priv.hash_size(), 0);
	hash[0] = 1;
	hash[1] = 1;
	hash[2] = 1;

	cout << "SIGNING" << endl << hash;
	priv.sign (hash, signature, 2, priv.hash_size() *priv.hash_size(), r);
	cout << "SIGNATURE" << endl << signature;
	if (pub.verify (signature, hash, 2) )
		cout << "VERIFY FAIL" << endl;
	else	cout << "VERIFY OK" << endl;
	return 0;
}

