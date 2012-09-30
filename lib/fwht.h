
#ifndef _fwht_h_
#define _fwht_h_

#include "codecrypt.h"

using namespace ccr;

//parameters MUST be of 2^m size.
void fwht_dyadic_multiply (const bvector&, const bvector&, bvector&);

#endif

