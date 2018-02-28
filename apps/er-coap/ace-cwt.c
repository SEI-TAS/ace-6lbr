#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "cn-cbor/cn-cbor.h"
#include "cwt.h"
#include "cfs/cfs.h"
#include "dtls.h"


#ifdef USE_CBOR_CONTEXT
#define CBOR_CONTEXT_PARAM , NULL
#else
#define CBOR_CONTEXT_PARAM
#endif



static void authenticate(unsigned long *claim, cwt *token, const cn_cbor* cb, char* out, char** end, int indent) {
  if (!cb)
    goto done;
  int i;
  cn_cbor* cp;

  printf("Type: %d\n",cb->type);
  switch (cb->type) {

  case CN_CBOR_ARRAY: goto sequence;
  case CN_CBOR_MAP: goto sequence;

  sequence:
    for (cp = cb->first_child; cp; cp = cp->next) {
      authenticate(claim, token, cp, out, &out, indent+2);
    }
    break;

  case CN_CBOR_BYTES: 
    if(token->in_cnf > 0){
      printf("\ncnf CLM: %d\n", *claim);
    }
    printf("HEX:");
    for (i=0; i<cb->length; i++)
      printf("%02x", cb->v.str[i]);
    switch(*claim){
      case 1:
        token->cnf = (char *) malloc(cb->length+1);
        strncpy(token->cnf, cb->v.str, cb->length);
        token->cnf[cb->length+1] = '\0';
        printf("cnf is %s\n", token->cnf);
        token->in_cnf = 1;
        read_cbor(cb->v.str, cb->length);
        token->in_cnf = 0;
        break;
      case 7:
        token->cti = (char *) malloc(cb->length+1);
        strncpy(token->cti, cb->v.str, cb->length);
        token->cti[cb->length+1] = '\0';
        printf("cti is %s\n", token->cti);
        break;
      case 0:
        token->kid = (char *) malloc(cb->length+1);
        strncpy(token->kid, cb->v.str, cb->length);
        token->kid[cb->length+1] = '\0';
        printf("kid is %s\n", token->kid);
        break;
      case 3:
        token->k = (char *) malloc(cb->length+1);
        strncpy(token->k, cb->v.str, cb->length);
        token->k[cb->length+1] = '\0';
        printf("k is %s\n", token->k);
        char *token_file = "tokens";
        int fd_write, n;
        fd_write = cfs_open(token_file, CFS_WRITE);
        if(fd_write != -1){
          n = cfs_write(fd_write, token->kid, cb->length);  
          n = cfs_write(fd_write, ":", 1);  
          n = cfs_write(fd_write, token->k, cb->length);  
          cfs_close(fd_write);
        }
        break;

    }
    break;

  case CN_CBOR_TEXT:
    printf("LEN: %d\n",cb->length);
    printf("\nTXT: %s\n", cb->v.str);
    printf("CLM: %d\n", *claim);

    switch(*claim){
      case 1:
        token->iss = (char *) malloc(cb->length+1);
        strncpy(token->iss, cb->v.str, cb->length);
        token->iss[cb->length+1] = '\0';
        printf("iss is %s\n", token->iss);
        break;
      case 2:
        token->sub = (char *) malloc(cb->length+1);
        strncpy(token->sub, cb->v.str, cb->length);
        token->sub[cb->length+1] = '\0';
        printf("sub is %s\n", token->sub);
        break;
      case 3:
        token->aud = (char *) malloc(cb->length+1);
        strncpy(token->aud, cb->v.str, cb->length);
        token->aud[cb->length+1] = '\0';
        printf("aud is %s\n", token->aud);
        break;
      case 12:
        printf("It's 12\n");
        token->sco = (char *) malloc(cb->length+1);
        strncpy(token->sco, cb->v.str, cb->length);
        token->sco[cb->length+1] = '\0';
        printf("sco is %s\n", token->sco);
        break;
    }
    break;

  case CN_CBOR_UINT:
    printf("UINT: %lu\n", cb->v.uint);
    if(cb->v.uint < 256){
      *claim = cb->v.uint;
      printf("CLM: %d\n",*claim);
    }
    else {
      switch(*claim){
      case 4: token->exp = cb->v.uint; break;
      case 5: token->nbf = cb->v.uint; break;
      case 6: token->iat = cb->v.uint; break;
      }
      *claim = 0;
    }
      
    break;


  default: break;
  }

  return 0;

done:
  *end = out;
}


unsigned char* read_cbor(const unsigned char* payload, int i_len) {
  char buf[1000];
  char *bufend;
  cwt t;
  cwt *token = &t;
  /* token->sub = "a"; */
  unsigned long claim = 0;
  cn_cbor *cb = cn_cbor_decode(payload, i_len CBOR_CONTEXT_PARAM, 0);
  if (cb) {
    authenticate(&claim, token, cb, buf, &bufend, 0);
    return 0;
  }
  return 1;
}

unsigned char* read_cose(const unsigned char* payload, int i_len) {
  char buf[1000];
  char *bufend;
  cosewt cose-token;
  cosewt *token = &cose-token;
  unsigned long claim = 0;
  cn_cbor *cb = cn_cbor_decode(payload, i_len CBOR_CONTEXT_PARAM, 0);
  un_cose(&claim, token, cb, buf, &bufend, 0);
  buf = decrypt_cose(token);
  read_cbor(buf, sizeof(buf));

}


static void un_cose(unsigned long *claim, cosewt *token, const cn_cbor* cb, char* out, char** end, int indent) {
  if (!cb)
    goto done;
  int i;
  cn_cbor* cp;

  printf("Type: %d\n",cb->type);
  switch (cb->type) {

  case CN_CBOR_ARRAY: goto sequence;
  case CN_CBOR_MAP: goto sequence;

  sequence:
    for (cp = cb->first_child; cp; cp = cp->next) {
      un_cose(claim, token, cp, out, &out, indent+2);
    }
    break;

  case CN_CBOR_BYTES:
    if (cb->length == 13){
      token->nonce = (char *) malloc(cb->length+1);
      strncpy(token->nonce, cb->v.str, cb->length);
      token->nonce[cb->length+1] = '\0';
      printf("nonce is %s\n", token->nonce);
      break;
    }
    if (cb->length > 13){
      token->pay = (char *) malloc(cb->length+1);
      strncpy(token->pay, cb->v.str, cb->length);
      token->pay[cb->length+1] = '\0';
      printf("pay is %s\n", token->pay);
      break;
    }


    break;
  default: break;
  }


}

char* decrypt_cose(cosewt* token){
  char* plaintext;
  plaintext = dtls_ccm_decrypt_message(context, 16, 64, token->nonce, token->pay, sizeof(token->pay), NULL, 0); 
  return plaintext;
}
