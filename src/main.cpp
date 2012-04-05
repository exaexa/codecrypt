
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
	uint i, j;
	primitiverng r;
	r.seed (0);

	ccr::mce::privkey priv;
	ccr::mce::pubkey pub;
	ccr::mce::generate (pub, priv, r, 8, 4);

	return 0;
}

