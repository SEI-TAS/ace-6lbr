#include "dtls_crypto.h"
#include "aes/rijndael.h"

#define A_DATA_LEN 0

extern static struct dtls_cipher_context_t *dtls_cipher_context_get(void);
extern static void dtls_cipher_context_release(void);

int
dtls_decrypt_with_nounce_len(const unsigned char *src, size_t length,
	     unsigned char *buf,
	     unsigned char *nounce, size_t nounce_len,
	     unsigned char *key, size_t keylen)
{
  int ret;
  struct dtls_cipher_context_t *ctx = dtls_cipher_context_get();

  ret = rijndael_set_key_enc_only(&ctx->data.ctx, key, 8 * keylen);
  if (ret < 0) {
    /* cleanup everything in case the key has the wrong size */
    printf("Cannot set rijndael key\n");
    goto error;
  }

  if (src != buf)
    memmove(buf, src, length);

  unsigned char A_DATA[A_DATA_LEN];

  ret = dtls_ccm_decrypt_message(&ccm_ctx->ctx, 8 /* M */,
				 max(2, 15 - nounce_len),
				 nounce,
				 buf, srclen,
				 A_DATA, A_DATA_LEN);

error:
  dtls_cipher_context_release();
  return ret;
}