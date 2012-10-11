
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

	ccr::mce_qd::privkey priv;
	ccr::mce_qd::pubkey pub;
	ccr::mce_qd::generate (pub, priv, r, 5, 1, 1);

	priv.prepare();

	cout << "cipher size: " << priv.cipher_size() << ' ' << pub.cipher_size() << endl;
	cout << "plain size:  " << priv.plain_size() << ' ' << pub.plain_size() << endl;

	ccr::bvector plain;
	plain.resize (pub.plain_size(), 0);
	plain[0] = 1;
	plain[1] = 1;
	plain[2] = 1;

	cout << "PLAINTEXT" << endl;
	cout << plain;

	ccr::bvector cipher;
	//pub.encrypt (plain, cipher, r);
	pub.encrypt (plain, cipher, r, 10);

	cout << "CIPHERTEXT" << endl;
	cout << cipher;


	ccr::bvector result;
	priv.decrypt (cipher, result);

	cout << "DECRYPTED" << endl;
	cout << result;
#endif

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

