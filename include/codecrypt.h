
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <vector>

//little STL helper, because writing (*this)[i] everywhere is clumsy
#define _ccr_declare_vector_item \
	inline reference item(size_type n) \
		{ return (*this)[n]; }; \
	inline const_reference item(size_type n) const \
		{ return (*this)[n]; };
#define _ccr_declare_matrix_item \
	inline value_type::reference \
		item(size_type n, size_type m) \
		{ return (*this)[n][m]; }; \
	inline value_type::const_reference \
		item(size_type n, size_type m) const \
		{ return (*this)[n][m]; };

namespace ccr
{

/*
 * typedef. uint should be able to comfortably hold the field elements of
 * underlying calculations (esp. with polynomials. Switching to 64bits is
 * adviseable when computing with n=64K and larger.
 */
typedef unsigned int uint;

/*
 * vector over GF(2). We rely on STL's vector<bool> == bit_vector
 * specialization for space efficiency.
 */
class polynomial;
class gf2m;
class bvector : public std::vector<bool>
{
protected:
	_ccr_declare_vector_item
public:
	uint hamming_weight();
	void add (const bvector&);
	void add_range (const bvector&, uint, uint);
	void add_offset (const bvector&, uint);
	bool operator* (const bvector&); //dot product
	bool zero() const;

	void to_poly (polynomial&, gf2m&);
	void from_poly (const polynomial&, gf2m&);

	void to_poly_cotrace (polynomial&, gf2m&);
	void from_poly_cotrace (const polynomial&, gf2m&);

	void colex_rank (bvector&);
	void colex_unrank (bvector&, uint n, uint k);
};

/*
 * pseudorandom number generator. Meant to be inherited and
 * instantiated by the user
 */
class prng
{
public:
	virtual uint random (uint) = 0;
};

/*
 * matrix over GF(2) is a vector of columns
 */
class permutation;
class matrix : public std::vector<bvector>
{
protected:
	_ccr_declare_vector_item
	_ccr_declare_matrix_item

public:
	uint width() const {
		return size();
	}

	uint height() const {
		if (size() ) return item (0).size();
		return 0;
	}

	void resize2 (uint w, uint h, bool def = 0);

	matrix operator* (const matrix&);
	void mult (const matrix&); //right multiply - this*param

	void zero ();
	void unit (uint);

	void compute_transpose (matrix&);
	bool mult_vecT_left (const bvector&, bvector&);
	bool mult_vec_right (const bvector&, bvector&);
	bool compute_inversion (matrix&,
	                        bool upper_tri = false,
	                        bool lower_tri = false);

	bool set_block (uint, uint, const matrix&);
	bool add_block (uint, uint, const matrix&);
	bool set_block_from (uint, uint, const matrix&);
	bool add_block_from (uint, uint, const matrix&);

	bool get_left_square (matrix&);
	bool strip_left_square (matrix&);
	bool get_right_square (matrix&);
	bool strip_right_square (matrix&);
	void extend_left_compact (matrix&);

	void generate_random_invertible (uint, prng&);
	void generate_random_with_inversion (uint, matrix&, prng&);
	bool create_goppa_generator (matrix&, permutation&, prng&);
	bool create_goppa_generator (matrix&, const permutation&);
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
	void compute_inversion (permutation&) const;

	void generate_random (uint n, prng&);

	template<class V> void permute (const V&a, V&r) const {
		r.resize (a.size() );
		for (uint i = 0; i < size(); ++i) r[item (i) ] = a[i];
	}

	void permute_rows (const matrix&, matrix&) const;
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

	std::vector<uint> log, antilog;

	uint add (uint, uint);
	uint mult (uint, uint);
	uint exp (uint, int);
	uint exp (int);
	uint inv (uint);
	uint sq_root (uint);
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
	bool one() const;
	void shift (uint);

	uint eval (uint, gf2m&) const;
	void add (const polynomial&, gf2m&);
	void mult (const polynomial&, gf2m&);
	void add_mult (const polynomial&, uint mult, gf2m&);
	void mod (const polynomial&, gf2m&);
	void div (polynomial&, polynomial&, gf2m&);
	void divmod (polynomial&, polynomial&, polynomial&, gf2m&);
	void square (gf2m&);
	void inv (polynomial&, gf2m&);
	void make_monic (gf2m&);

	void sqrt (vector<polynomial>&, gf2m&);
	polynomial gcd (polynomial, gf2m&);
	void mod_to_fracton (polynomial&, polynomial&, polynomial&, gf2m&);

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
	permutation hperm;
	gf2m fld;

	// derivable things not needed in actual key
	matrix h;
	std::vector<polynomial> sqInv;

	int prepare();
	int decrypt (const bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, uint, prng&);

	uint cipher_size() {
		return Pinv.size();
	}
	uint plain_size() {
		return Sinv.width();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
};

class pubkey
{
public:
	matrix G;
	uint t;

	int encrypt (const bvector&, bvector&, prng&);
	int verify (const bvector&, const bvector&, uint);

	uint cipher_size() {
		return G.width();
	}
	uint plain_size() {
		return G.height();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
};

int generate (pubkey&, privkey&, prng&, uint m, uint t);
}

/*
 * classical Niederreiter
 */
namespace nd
{
class privkey
{
public:
	matrix Sinv;
	permutation Pinv;
	polynomial g;
	gf2m fld;

	//derivable.
	std::vector<polynomial> sqInv;

	int decrypt (const bvector&, bvector&);
	int sign (const bvector&, bvector&, uint, uint, prng&);
	int prepare();

	uint cipher_size() {
		return Sinv.size();
	}
	uint plain_size() {
		return Pinv.size();
	}
	uint plain_weight() {
		return g.degree();
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
};

class pubkey
{
public:
	matrix H;
	uint t;

	int encrypt (const bvector&, bvector&);
	int verify (const bvector&, const bvector&, uint);

	uint cipher_size() {
		return H.height();
	}
	uint plain_size() {
		return H.width();
	}
	uint plain_weight() {
		return t;
	}
	uint hash_size() {
		return cipher_size();
	}
	uint signature_size() {
		return plain_size();
	}
};

int generate (pubkey&, privkey&, prng&, uint m, uint t);
}

/*
 * compact Quasi-dyadic McEliece
 * according to Misoczki, Barreto, Compact McEliece Keys from Goppa Codes.
 *
 * Good security, extremely good speed with extremely reduced key size.
 * Recommended for encryption, but needs some plaintext conversion -- either
 * Fujisaki-Okamoto or Kobara-Imai are known to work good.
 */
namespace mce_qd
{
class privkey
{
public:
	std::vector<uint> essence;
	gf2m fld;   //we fix q=2^fld.m=fld.n, n=q/2
	uint T;     //the QD's t parameter is 2^T.
	uint hperm; //dyadic permutation of H to G
	permutation block_perm; //order of blocks
	uint block_count; //blocks >= block_count are shortened-out
	std::vector<uint> block_perms; //dyadic permutations of blocks

	//derivable stuff
	std::vector<uint> Hsig; //signature of canonical H matrix
	std::vector<uint> support; //computed goppa support
	polynomial g; //computed goppa polynomial

	int decrypt (const bvector&, bvector&);
	int prepare();

	uint cipher_size() {
		return 0; //TODO
	}
	uint plain_size() {
		return 0; //TODO
	}
};

class pubkey
{
public:
	uint T;
	matrix M;

	int encrypt (const bvector&, bvector&, prng&);

	uint cipher_size() {
		return 0; //TODO
	}
	uint plain_size() {
		return 0; //TODO
	}
};

int generate (pubkey&, privkey&, prng&, uint m, uint T, uint b);
}

/*
 * McEliece on Overlapping Chain of Goppa Codes
 *
 * Similar to Hamdi's Chained BCH Codes, but with improvement.
 *
 * This is experimental, unverified, probably insecure, but practical scheme
 * that achieves good speed, probability and key size for full decoding that is
 * needed to produce signatures. Technique is described in documentation, with
 * some (probably sufficient) notes in source code.
 *
 * Note that encryption using this scheme is impossible, as there is only an
 * extremely tiny probability of successful decoding.
 */
namespace mce_oc
{
class privkey
{
public:
	matrix Sinv;
	permutation Pinv;
	gf2m fld;

	class subcode
	{
	public:
		polynomial g;
		permutation hperm;

		//derivables
		matrix h;
		std::vector<polynomial> sqInv;
	};

	std::vector<subcode> codes;

	int sign (const bvector&, bvector&, uint, uint, prng&);
	int prepare();

	uint hash_size() {
		return Pinv.size();
	}
	uint signature_size() {
		return Sinv.size();
	}
};

class pubkey
{
public:
	matrix G;
	uint n, t;

	int verify (const bvector&, const bvector&, uint);

	uint hash_size() {
		return G.width();
	}
	uint signature_size() {
		return G.height();
	}
};

//n is the number of subcodes used
int generate (pubkey&, privkey&, prng&, uint m, uint t, uint n);
}

} //namespace ccr

//global overload for iostream operators
#include <iostream>

std::ostream& operator<< (std::ostream&o, const ccr::polynomial&);
std::ostream& operator<< (std::ostream&o, const ccr::permutation&);
std::ostream& operator<< (std::ostream&o, const ccr::gf2m&);
std::ostream& operator<< (std::ostream&o, const ccr::matrix&);
std::ostream& operator<< (std::ostream&o, const ccr::bvector&);


#endif // _CODECRYPT_H_

