#ifndef TINYDTLS_AES_H
#define TINYDTLS_AES_H

int
dtls_decrypt_with_nounce_len(const unsigned char *src, size_t length,
	     unsigned char *buf,
	     unsigned char *nounce, size_t nounce_len,
	     unsigned char *key, size_t keylen);

#endif // TINYDTLS_AES_H