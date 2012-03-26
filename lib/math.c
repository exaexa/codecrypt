
#include "math.h"

#include <stdint.h>

void ccr_vec_xor (int bits, ccr_mtx a, ccr_mtx b, ccr_mtx r)
{
	/* possible speedup for wideword architectures
	while(bits>=32) {
		*(uint32_t*)r = *(uint32_t*)a ^ *(uint32_t*)b;
		a+=4;b+=4;r+=4;bits-=32;
	} */
	while (bits > 0) {
		* (uint8_t*) r = * (uint8_t*) a ^ * (uint8_t*) b;
		a += 1;
		b += 1;
		r += 1;
		bits -= 8;
	}
	/* we can safely ignore padding bytes at the end of the vector */
}

void ccr_vec_and (int bits, ccr_mtx a, ccr_mtx b, ccr_mtx r)
{
	while (bits > 0) {
		* (uint8_t*) r = * (uint8_t*) a & * (uint8_t*) b;
		a += 1;
		b += 1;
		r += 1;
		bits -= 8;
	}
}

int ccr_vec_parity (int bits, ccr_mtx a)
{
	/* first, xor everything to one byte */
	uint8_t b = 0;
	while (bits >= 8) {
		b ^= * (uint8_t*) a;
		a += 1;
		bits -= 8;
	}
	if (bits > 0) /* overflow padding bits away */
		b ^= * (uint8_t*) a << (8 - bits);

	/* squash the result in a single bit */
	b ^= b >> 4;
	b ^= b >> 2;
	b ^= b >> 1;
	return b & 1;
}

void ccr_vec_bit_set (ccr_mtx a, int offset, int bit)
{
	if (bit)
		( (uint8_t*) a) [offset/8] |= (uint8_t) (1 << (offset % 8) );
	else
		( (uint8_t*) a) [offset/8] &= ~ (uint8_t) (1 << (offset % 8) );
}

uint8_t ccr_vec_bit_get (ccr_mtx a, int offset)
{
	return 1 & ( ( (uint8_t*) a) [offset/8] >> (offset % 8) );
}

void ccr_mtx_add (int cols, int rows,
                  ccr_mtx a, ccr_mtx b, ccr_mtx r)
{
	int i, t;
	for (i = 0; i < cols; ++i) {
		t = ccr_mtx_vec_offset (rows, i);
		ccr_vec_xor (rows, a + t, b + t, r + t);
	}
}

int ccr_mtx_dotproduct (ccr_mtx a, ccr_mtx b,
                        int aoff, int aheight, int boff, int len)
{
	uint8_t r = 0;
	int i;
	for (i = 0; i < len; ++i)
		r ^= ccr_vec_bit_get (a + ccr_mtx_vec_offset (aheight, i), aoff)
		     & ccr_vec_bit_get (b + ccr_mtx_vec_offset (len, boff), i);
	return r;
}

void ccr_mtx_multiply (int rows, int veclen, int cols,
                       ccr_mtx a, ccr_mtx b, ccr_mtx r)
{
	/* TODO use faster algorithm */

	int i, j;
	for (i = 0; i < cols; ++i)
		for (j = 0; j < rows; ++j)
			ccr_vec_bit_set (r + ccr_mtx_vec_offset (rows, i), j,
			                 ccr_mtx_dotproduct (a, b,
			                                     j, rows, i,
			                                     veclen) );
}
