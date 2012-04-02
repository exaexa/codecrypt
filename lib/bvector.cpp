
#include "codecrypt.h"
using namespace ccr;

uint bvector::hamming_weight()
{
	uint r = 0;
	for (uint i = 0; i < size(); ++i) if ( (*this) [i]) ++r;
	return r;
}

void bvector::add (const bvector&a)
{
	if (a.size() > size() ) resize (a.size(), 0);
	for (uint i = 0; i < size(); ++i)
		item (i) = item (i) ^ a[i];
}

bool bvector::operator* (const bvector&a)
{
	bool r = 0;
	uint s = size(), i;
	if (s > a.size() ) s = a.size();
	for (i = 0; i < s; ++i) r ^= (item (i) &a[i]);
	return r;
}

