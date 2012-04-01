
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <vector>

namespace ccr
{

typedef unsigned int uint;

/*
 * vector over GF(2). We rely on STL's vector<bool> == bit_vector
 * specialization for efficiency.
 */
class bvector : public std::vector<bool>
{
	//STL wraparound, because writing (*this)[i] is clumsy
	inline reference item (size_type n) {
		return (*this) [n];
	}
public:
	uint hamming_weight();
};

/*
 * pseudorandom number generator. Meant to be inherited and
 * instantiated by the user
 */
class prng
{
public:
	virtual int random (uint) = 0;
	virtual void request_seed (uint) = 0;
};

/*
 * matrix over GF(2) is a vector of columns
 */
class matrix : public std::vector<bvector>
{
	inline reference item (size_type n) {
		return (*this) [n];
	}
public:
	matrix operator* (const matrix&);

	bool compute_inversion (matrix&);
	void generate_random_invertible (uint, prng&);
	void unit (uint);
	void compute_transpose (matrix&);
};

/*
 * permutation is stored as transposition table ordered from zero
 * e.g. (13)(2) is [2,1,0]
 */
class permutation : public std::vector<uint>
{
	inline reference item (size_type n) {
		return (*this) [n];
	}
public:
	void compute_inversion (permutation&);

	void generate_random (uint n, prng&);
	void permute (const bvector&, bvector&);
	void permute (const matrix&, matrix&);
	void permute_rows (const matrix&, matrix&);
};

/*
 * polynomial over GF(2) is effectively a vector with a_n binary values
 * with some added operations.
 */
class polynomial : public bvector
{
	inline reference item (size_type n) {
		return (*this) [n];
	}
public:
	bool is_irreducible();

	void generate_random_irreducible (uint n, prng&);
};

/*
 * classical McEliece
 */
namespace mce
{
class privkey
{
public:
	matrix Sinv;
	permutation Pinv;

	matrix h;
	permutation hsys;

	polynomial g;
	matrix sqInv; //"cache"

	int decrypt (const bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, prng&);
};

class pubkey
{
public:
	matrix G;
	uint t;
	int encrypt (const bvector&, bvector&, prng&);
	int verify (const bvector&, const bvector&, uint);
};

int generate (pubkey&, privkey&, prng&);
}

/*
 * classical Niederreiter
 */
namespace nd
{
class privkey
{
public:
	// TODO

	int decrypt (const bvector&, bvector&);
	int sign (const bvector&hash, bvector&sig, uint, prng&);
};

class pubkey
{
public:
	matrix H;
	uint t;

	int encrypt (const bvector&, bvector&, prng&);
	int verify (const bvector&sig, const bvector&hash, uint);
};

int generate (pubkey&, privkey&, prng&);
}

} //namespace ccr

#endif // _CODECRYPT_H_

