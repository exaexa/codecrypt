
#include "codecrypt.h"
using namespace ccr;

uint bvector::hamming_weight()
{
	uint r = 0;
	for (uint i = 0; i < size(); ++i) if ( (*this) [i]) ++r;
	return r;
}

