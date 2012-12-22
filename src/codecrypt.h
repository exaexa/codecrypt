
/*
 * This file is part of Codecrypt.
 *
 * Codecrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Codecrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Codecrypt. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <string>
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

/*
 * data serialization format
 */

class sencode
{
public:
	virtual std::string encode() = 0;
	virtual void destroy() {}
};

bool sencode_decode (const std::string&, sencode**);
void sencode_destroy (sencode*);

class sencode_list: public sencode
{
public:
	std::vector<sencode*> items;

	virtual std::string encode();
	virtual void destroy();
};

class sencode_int: public sencode
{
public:
	unsigned int i;
	sencode_int (unsigned int I) {
		i = I;
	}

	virtual std::string encode();
};

class sencode_bytes: public sencode
{
public:
	std::string b;
	sencode_bytes (const std::string&s) {
		b = s;
	}

	virtual std::string encode();
};

/*
 * typedef. uint should be able to comfortably hold the field elements of
 * underlying calculations (esp. with polynomials. Switching to 64bits is
 * adviseable when computing with n=64K and larger.
 */
typedef unsigned int uint;

/*
 * vector over GF(2). We rely on STL's vector<bool> == bit_vector
 * specialization for space efficiency.
 *
 * TODO. This is great, but some operations (ESPECIALLY add()) could be done
 * blockwise for O(cpu_word_size) speedup. Investigate/implement that. haha.
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
	void set_block (const bvector&, uint);
	void get_block (uint, uint, bvector&) const;
	bool operator* (const bvector&); //dot product
	bool zero() const;

	void to_poly (polynomial&, gf2m&) const;
	void from_poly (const polynomial&, gf2m&);

	void to_poly_cotrace (polynomial&, gf2m&) const;
	void from_poly_cotrace (const polynomial&, gf2m&);

	void colex_rank (bvector&) const;
	void colex_unrank (bvector&, uint n, uint k) const;

	sencode* serialize();
	bool unserialize (sencode*);
};

/*
 * pseudorandom number generator. Meant to be inherited and
 * instantiated by the library user
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

	bool create_goppa_generator_dyadic (matrix&, uint&, prng&);
	bool create_goppa_generator_dyadic (matrix&, uint);

	sencode* serialize();
	bool unserialize (sencode*);
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
	void generate_identity (uint n) {
		resize (n);
		for (uint i = 0; i < n; ++i)
			item (i) = i;
	}

	//TODO permute_inv is easy, do it everywhere
	template<class A, class R> void permute (const A&a, R&r) const {
		r.resize (a.size() );
		for (uint i = 0; i < size(); ++i) r[item (i) ] = a[i];
	}

	void permute_rows (const matrix&, matrix&) const;

	//work-alike for dyadic permutations.
	template<class A, class R> static bool permute_dyadic
	(uint sig, const A&a, R&r) {

		//check if the thing has size 2^n
		uint s = a.size();
		while (s > 1) {
			if (s & 1) return false;
			s >>= 1;
		}

		if (sig >= a.size() ) return false;

		r.resize (a.size() );

		uint i, t, x;
		for (i = 0; i < a.size(); ++i) {
			r[sig] = a[i];

			//flip the correct bit in signature
			t = i + 1;
			x = 1;
			while (! (t & 1) ) {
				t >>= 1;
				x <<= 1;
			}
			sig ^= x;
		}

		return true;
	}

	sencode* serialize();
	bool unserialize (sencode*);
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

	sencode* serialize();
	bool unserialize (sencode*);
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
	uint head() {
		int t;
		if ( (t = degree() ) >= 0) return item (t);
		else return 0;
	}
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
	void ext_euclid (polynomial&, polynomial&, polynomial&, gf2m&, int);

	bool is_irreducible (gf2m&) const;
	void generate_random_irreducible (uint s, gf2m&, prng&);

	bool compute_square_root_matrix (std::vector<polynomial>&, gf2m&);
	void compute_goppa_check_matrix (matrix&, gf2m&);

	sencode* serialize();
	bool unserialize (sencode*);
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
	int decrypt (const bvector&, bvector&, bvector&);
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
	uint error_count() {
		return g.degree();
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	matrix G;
	uint t;

	int encrypt (const bvector&, bvector&, prng&);
	int encrypt (const bvector&, bvector&, const bvector&);
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
	uint error_count() {
		return t;
	}

	sencode* serialize();
	bool unserialize (sencode*);
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
	uint signature_weight() {
		return plain_weight();
	}

	sencode* serialize();
	bool unserialize (sencode*);
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
	uint signature_weight() {
		return plain_weight();
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint m, uint t);
}

/*
 * compact Quasi-dyadic McEliece
 * according to Misoczki, Barreto, Compact McEliece Keys from Goppa Codes.
 *
 * Good security, extremely good speed with extremely reduced key size.
 * Recommended for encryption, but needs some plaintext conversion -- either
 * Fujisaki-Okamoto or Kobara-Imai are known to work good. Without the
 * conversion, the encryption itself is extremely weak.
 */
namespace mce_qd
{
class privkey
{
public:
	std::vector<uint> essence;
	gf2m fld;   //we fix q=2^fld.m=fld.n, n=q/2
	uint T;     //the QD's t parameter is 2^T.
	permutation block_perm; //order of blocks
	std::vector<uint> block_perms; //dyadic permutations of blocks
	permutation hperm; //block permutation of H block used to get G

	//derivable stuff
	//cols of check matrix of g^2(x)
	std::vector<polynomial> Hc;
	//pre-permuted positions of support rows
	std::vector<uint> support_pos;

	int decrypt (const bvector&, bvector&);
	int decrypt (const bvector&, bvector&, bvector&);
	int prepare();

	uint cipher_size() {
		return (1 << T) * hperm.size();
	}
	uint plain_size() {
		return (1 << T) * (hperm.size() - fld.m);
	}
	uint error_count() {
		return 1 << T;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

class pubkey
{
public:
	uint T;
	matrix qd_sigs;

	int encrypt (const bvector&, bvector&, prng&);
	int encrypt (const bvector&, bvector&, const bvector&);

	uint cipher_size() {
		return plain_size() + qd_sigs[0].size();
	}
	uint plain_size() {
		return (1 << T) * qd_sigs.size();
	}
	uint error_count() {
		return 1 << T;
	}

	sencode* serialize();
	bool unserialize (sencode*);
};

int generate (pubkey&, privkey&, prng&, uint m, uint T, uint b);
}

//global overload for iostream operators
#include <iostream>

std::ostream& operator<< (std::ostream&o, const polynomial&);
std::ostream& operator<< (std::ostream&o, const permutation&);
std::ostream& operator<< (std::ostream&o, const gf2m&);
std::ostream& operator<< (std::ostream&o, const matrix&);
std::ostream& operator<< (std::ostream&o, const bvector&);


#endif // _CODECRYPT_H_

