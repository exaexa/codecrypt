
#ifndef _decoding_h_
#define _decoding_h_

#include "codecrypt.h"

using namespace ccr;

void compute_error_locator (polynomial&syndrome,
                            gf2m&fld,
                            polynomial&goppa,
                            std::vector<polynomial>& sqInv,
                            polynomial&loc);

bool evaluate_error_locator_dumb (polynomial&el, bvector&ev, gf2m&fld);
bool evaluate_error_locator_trace (polynomial&el, bvector&ev, gf2m&fld);

#endif
