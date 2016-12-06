#ifndef _PRF_HMAC_H_
#define _PRF_HMAC_H_

void hmac_sha1(unsigned char *key, int key_len, unsigned char *text, int text_len, unsigned char *digest);

void hmac_md5(unsigned char *key, int key_len, unsigned char *text, int text_len, unsigned char *digest);

int p_sha1(unsigned char *secret, int secret_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen);

int p_md5(unsigned char *secret, int secret_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen);

int tls_prf(unsigned char *secret, int secret_len, unsigned char *label, int label_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen);

#endif
