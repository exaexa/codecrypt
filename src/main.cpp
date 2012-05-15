
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
	return 0;
}

