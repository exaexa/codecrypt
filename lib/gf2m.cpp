
#include "codecrypt.h"

using namespace ccr;

#include <iostream>
using namespace std;

/*
 * helpful stuff for arithmetic in GF(2^m) - polynomials over GF(2).
 */

int gf2p_degree (uint p)
{
	int r = -1;
	for (int i = 0; p; p >>= 1, ++i) r = i;
	return r;
}

uint gf2p_mod (uint a, uint p)
{
	if (!p) return 0;
	int t, degp = gf2p_degree (p);
	while ( (t = gf2p_degree (a) ) >= degp)
		a ^= p << (t - degp);
	return a;
}

uint gf2p_gcd (uint a, uint b)
{
	uint c;
	if (!a) return b;
	while (b) {
		c = gf2p_mod (a, b);
		a = b;
		b = c;
	}
	return a;
}

uint gf2p_modmult (uint a, uint b, uint p)
{
	a = gf2p_mod (a, p);
	b = gf2p_mod (b, p);
	uint r = 0;
	uint d = 1 << gf2p_degree (p);
	while (a) {
		if (a & 1) r ^= b;
		a >>= 1;
		b <<= 1;
		if (b <= d) b ^= p;
	}
	return r;
}

bool is_irreducible_gf2_poly (uint p)
{
	if (!p) return false;
	int d = gf2p_degree (p) / 2;
	uint test = 2; //x^1+0
	for (int i = 0; i < d; ++i) {
		test = gf2p_modmult (test, test, p);

		if (gf2p_gcd (test ^ 2 /* test - x^1 */, p) != 1)
			return false;
	}
	return true;
}

bool gf2m::create (uint M)
{
	if (M < 1) return false; //too small.
	m = M;
	n = 1 << m;
	if (!n) return false; //too big.
	for (uint t = 1 + (1 << m), e = 1 << (1 + m); t < e; t += 2)
		if (is_irreducible_gf2_poly (t) ) {
			poly = t;
			return true;
		}
	return false;
}

/*
uint gfn_mult(uint a, uint b, uint n)
{
	uint irp=0;
	while(n) { irp=(irp<<1)|1; n>>=1;}
	uint r=a*b;
	//TODO probably move this to own file
}

uint gfn_inv (uint a, uint n);

uint gfn_exp (uint a, sint k, uint n)
{
	if (!a) return 0;
	if (a == 1) return 1;
	if (k < 0) {
		a = gfn_inv (a, n);
		k = -k;
	}
	uint r = 1;
	while (k) {
		if (k & 1) r=gfn_mult(r,a,n);
		a=gfn_mult(a,a,n);
		k >>= 2;
	}
	return r;
}

uint gfn_inv (uint a, uint n)
{
	if (n == 2) return a;
	return gfn_exp (a, ( (sint) n) - 2, n);
}

*/
