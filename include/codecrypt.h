
#ifndef _CODECRYPT_H_
#define _CODECRYPT_H_

#ifdef __cplusplus
extern "C" {
#endif

struct ccr_mce_pubkey {
};

struct ccr_mce_privkey {
};

struct ccr_nd_pubkey {
};

struct ccr_nd_privkey {
};

int ccr_gen_mce(struct ccr_mce_pubkey*, struct ccr_mce_privkey*);
int ccr_gen_nd(struct ccr_nd_pubkey*, struct ccr_nd_privkey*);

int ccr_encrypt(struct ccr_mce_pubkey*, const char*, char*);
int ccr_decrypt(struct ccr_mce_privkey*, const char*, char*);

int ccr_sign(struct ccr_nd_privkey*, const char*, char*);
int ccr_read_signature(struct ccr_nd_pubkey*, const char*, char*);

#ifdef __cplusplus
}
#endif

#endif /* _CODECRYPT_H_ */

