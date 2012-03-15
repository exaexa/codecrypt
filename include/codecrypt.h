
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

int ccr_mce_gen(struct ccr_mce_pubkey*, struct ccr_mce_privkey*);
int ccr_mce_encrypt(struct ccr_mce_pubkey*, const char*, char*);
int ccr_mce_decrypt(struct ccr_mce_privkey*, const char*, char*);

int ccr_nd_gen(struct ccr_nd_pubkey*, struct ccr_nd_privkey*);
int ccr_nd_encrypt(struct ccr_nd_privkey*, const char*, char*);
int ccr_nd_decrypt(struct ccr_nd_pubkey*, const char*, char*);

#ifdef __cplusplus
}
#endif

#endif /* _CODECRYPT_H_ */

