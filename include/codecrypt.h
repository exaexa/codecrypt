
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#ifdef __cplusplus
extern "C" {
#endif

	/* codecrypt matrix/vector/whatever type */
	typedef char* ccr_mtx;

	/* macros for faster allocation/accessing */
#define ccr_mtx_alloc_size(veclen,nvec) ((((veclen)+7)/8)*(nvec))
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

		/* inverses of P and S matrices */
		ccr_mtx pinv, sinv;

		/* parity check matrix */
		ccr_mtx h;
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

		/* inverses of P and S matrices */
		ccr_mtx pinv, sinv;
	};

	int ccr_mce_gen (struct ccr_mce_pubkey*, struct ccr_mce_privkey*);
	int ccr_mce_encrypt (struct ccr_mce_pubkey*, const char*, char*);
	int ccr_mce_decrypt (struct ccr_mce_privkey*, const char*, char*);

	int ccr_nd_gen (struct ccr_nd_pubkey*, struct ccr_nd_privkey*);
	int ccr_nd_encrypt (struct ccr_nd_privkey*, const char*, char*);
	int ccr_nd_decrypt (struct ccr_nd_pubkey*, const char*, char*);

#ifdef __cplusplus
}
#endif

#endif /* _CODECRYPT_H_ */

