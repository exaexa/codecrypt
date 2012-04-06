
#ifndef _decoding_h_
#define _decoding_h_

#include "codecrypt.h"

using namespace ccr;
void syndrome_decode (bvector&syndrome,
                      gf2m&fld,
                      polynomial& gp,
                      std::vector<polynomial>& sqInv,
                      bvector&ev);

#endif
