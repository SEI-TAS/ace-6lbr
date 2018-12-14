/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#include <stdio.h>
#include "dtls_crypto.h"
#include "aes/rijndael.h"

#define A_DATA_LEN 0

extern struct dtls_cipher_context_t *dtls_cipher_context_get(void);
extern void dtls_cipher_context_release(void);

int
dtls_decrypt_with_nounce_len(const unsigned char *src, size_t srclen,
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
    return ret;
  }

  if (src != buf)
    memmove(buf, src, srclen);

  unsigned char A_DATA[A_DATA_LEN];

  ret = dtls_ccm_decrypt_message(&(&ctx->data)->ctx, 8 /* M */,
				 max(2, 15 - nounce_len),
				 nounce,
				 buf, srclen,
				 A_DATA, A_DATA_LEN);
  return ret;
}