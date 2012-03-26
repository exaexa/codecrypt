
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/* codecrypt matrix/vector/whatever type */
	typedef uint8_t* ccr_mtx;
	/* permutation as a list of transpositions */
	typedef int* ccr_perm;

	/* macros for faster allocation/accessing */
#define ccr_mtx_alloc_size(veclen,nvec) ((1+(((veclen)-1)/8))*(nvec))
#define ccr_mtx_vec_offset ccr_mtx_alloc_size

	struct ccr_mce_pubkey {
		/* params */
		int n, k, t;

		/* n*k G' pubkey matrix */
		ccr_mtx g;
	};

	struct ccr_mce_privkey {
		/* params */
		int n, k, t;

		/* goppa polynomial of degree t */
		ccr_mtx poly;

		/* inverse of S matrix */
		ccr_mtx sinv;

		/* inverse of P permutation */
		ccr_perm pinv;

		/* parity check matrix */
		ccr_mtx h;

		/* TODO: also consider storing the squareroot-mod-poly mtx,
		 * although it's derivable from poly. */
	};

	struct ccr_nd_pubkey {
		/* params */
		int n, k, t;

		/* pubkey matrix */
		ccr_mtx h;
	};

	struct ccr_nd_privkey {
		/* params */
		int n, k, t;

		/* goppa polynomial of degree t */
		ccr_mtx poly;

		/* inverse of S matrix */
		ccr_mtx sinv;

		/* inverse of P permutation */
		ccr_perm pinv;
	};

	/* actual functions */
	int ccr_mce_gen (struct ccr_mce_pubkey*, struct ccr_mce_privkey*);
	int ccr_mce_encrypt (struct ccr_mce_pubkey*, const uint8_t*, uint8_t*);
	int ccr_mce_decrypt (struct ccr_mce_privkey*, const uint8_t*, uint8_t*);

	int ccr_nd_gen (struct ccr_nd_pubkey*, struct ccr_nd_privkey*);
	int ccr_nd_encrypt (struct ccr_nd_privkey*, const uint8_t*, uint8_t*);
	int ccr_nd_decrypt (struct ccr_nd_pubkey*, const uint8_t*, uint8_t*);

	void ccr_set_log_func (void (*) (const char*) );
	void ccr_set_internal_allocator (void* (*) (size_t), void (*) (void*) );

#ifdef __cplusplus
}
#endif

#endif /* _CODECRYPT_H_ */

