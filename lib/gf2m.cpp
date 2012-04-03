
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

inline uint gf2p_add (uint a, uint b)
{
	return a ^ b;
}

void outbin (const char*n, uint x)
{
	cout << n << " = ";
	for (int i = 31; i >= 0; --i) cout << (1 & (x>>i) );
	cout << endl;
}

uint gf2p_mod (uint a, uint p)
{
	if (!p) return 0;
	int t, degp = gf2p_degree (p);
	while ( (t = gf2p_degree (a) ) >= degp) {
		a ^= p << (t - degp);
	}
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
		if (b >= d) b ^= p;
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

uint gf2m::add (uint a, uint b)
{
	return gf2p_add (a, b);
}

uint gf2m::mult (uint a, uint b)
{
	return gf2p_modmult (a, b, poly);
}

uint gf2m::exp (uint a, sint k)
{
	if (!a) return 0;
	if (a == 1) return 1;
	if (k < 0) {
		a = inv (a);
		k = -k;
	}
	uint r = 1;
	while (k) {
		if (k & 1) r = mult (r, a);
		a = mult (a, a);
		k >>= 1;
	}
	return r;
}

uint gf2m::inv (uint a)
{
	if (n == 2) return a;
	return exp (a, n - 2);
}

