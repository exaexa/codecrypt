
#ifndef _CCR_MATH_H_
#define _CCR_MATH_H_

#include "codecrypt.h"

void ccr_mtx_add (int, int, ccr_mtx, ccr_mtx, ccr_mtx);
void ccr_mtx_multiply (int, int, int, ccr_mtx, ccr_mtx, ccr_mtx);

int ccr_log2 (int, int*);
int ccr_gen_irred_poly (ccr_mtx, int);

int ccr_goppa_check_mtx (ccr_mtx, int, int, ccr_mtx*, int*, int*);

#endif

