
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <vector>

//STL wraparound, because writing (*this)[i] everywhere is clumsy
#define _ccr_declare_vector_item \
	inline reference item(size_type n) \
		{ return (*this)[n]; }; \
	inline const_reference item(size_type n) const \
		{ return (*this)[n]; };

namespace ccr
{

/*
 * typedefs. uint and sint should be able to comfortably hold the field
 * elements of underlying calculations (esp. with polynomials. Switching to
 * 64bits is adviseable when computing with n=64K and larger.
 */
typedef unsigned int uint;
typedef int sint;

/*
 * vector over GF(2). We rely on STL's vector<bool> == bit_vector
 * specialization for efficiency.
 */
class bvector : public std::vector<bool>
{
protected:
	_ccr_declare_vector_item
public:
	uint hamming_weight();
	void add (const bvector&);
	bool operator* (const bvector&); //dot product
};

/*
 * pseudorandom number generator. Meant to be inherited and
 * instantiated by the user
 */
class prng
{
public:
	virtual uint random (uint) = 0;
	virtual void seed (uint) = 0;
};

/*
 * matrix over GF(2) is a vector of columns
 */
class permutation;
class matrix : public std::vector<bvector>
{
protected:
	_ccr_declare_vector_item
public:
	uint width() const {
		return size();
	}

	uint height() const {
		if (size() ) return item (0).size();
		return 0;
	}

	matrix operator* (const matrix&);
	void mult (const matrix&);

	void compute_transpose (matrix&);
	bool compute_inversion (matrix&);
	void generate_random_invertible (uint, prng&);
	void unit (uint);
	bool get_left_square (matrix&);
	bool strip_left_square (matrix&);
	bool goppa_systematic_form (matrix&, permutation&, prng&);
};

/*
 * permutation is stored as transposition table ordered from zero
 * e.g. (13)(2) is [2,1,0]
 */
class permutation : public std::vector<uint>
{
protected:
	_ccr_declare_vector_item
public:
	void compute_inversion (permutation&);

	void generate_random (uint n, prng&);
	void permute (const bvector&, bvector&);
	void permute (const matrix&, matrix&);
	void permute_rows (const matrix&, matrix&);
};

/*
 * galois field of 2^m elements. Stored in an integer, for convenience.
 */

class gf2m
{
public:
	uint poly;
	uint n, m;

	bool create (uint m);

	uint add (uint, uint);
	uint mult (uint, uint);
	uint exp (uint, sint);
	uint inv (uint);
};

/*
 * polynomial over GF(2^m) is effectively a vector with a_n binary values
 * with some added operations.
 */
class polynomial : public std::vector<uint>
{
protected:
	_ccr_declare_vector_item
public:
	void strip();
	int degree() const;
	bool zero() const;
	uint eval (uint, gf2m&) const;
	void add (const polynomial&, gf2m&);
	void mod (const polynomial&, gf2m&);
	void mult (const polynomial&, gf2m&);
	polynomial gcd (polynomial, gf2m&);
	bool is_irreducible (gf2m&) const;
	void generate_random_irreducible (uint s, gf2m&, prng&);
	bool compute_square_root_matrix (std::vector<polynomial>&, gf2m&);
	void compute_goppa_check_matrix (matrix&, gf2m&);
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
	polynomial g;

	// derivable things not needed in actual key
	matrix h;
	permutation hperm;
	matrix sqInv;

	int decrypt (const bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, uint, prng&);
};

class pubkey
{
public:
	matrix G;
	uint t;
	int encrypt (const bvector&, bvector&, prng&);
	int verify (const bvector&, const bvector&, uint, uint);
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
	int sign (const bvector&hash, bvector&sig, uint, uint, prng&);
};

class pubkey
{
public:
	matrix H;
	uint t;

	int encrypt (const bvector&, bvector&, prng&);
	int verify (const bvector&sig, const bvector&hash, uint, uint);
};

int generate (pubkey&, privkey&, prng&);
}

} //namespace ccr

#endif // _CODECRYPT_H_

