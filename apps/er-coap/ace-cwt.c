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

#define A_DATA_LEN 0


static void authenticate(signed long *claim, cwt *token, const cn_cbor* cb, char* out, char** end, int indent) {
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
      case 25:
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
      case 2:
        token->kid = (char *) malloc(17);
        printf("kid len is %d\n", cb->length);
/*
        int i, j;
        unsigned char* lookupid;
        lookupid = (char *) malloc(17);
        i = 16 - cb->length;
        for (j = 0; j <= i - 1; j++){
          lookupid[j] = "0";
        }
        printf("kid len is %s\n", cb->length);
        strncpy(lookupid[j], cb->v.str, cb->length);
        for (i = 0; i < cb->length; i++){
          memcpy(lookupid[j], cb->v.str[i], 1);
          j++;
        }

        memcpy(token->kid, lookupid, 16);
*/

        strncpy(token->k, cb->v.str, cb->length);
        token->kid[cb->length+1] = '\0';
        printf("kid is %s\n", token->kid);
        break;
      case -1:
        token->k = (char *) malloc(cb->length+1);
        strncpy(token->k, cb->v.str, cb->length);
        token->k[cb->length+1] = '\0';
        printf("k is %s\n", token->k);
        char *token_file = "tokens";
        int fd_write, n;
        fd_write = cfs_open(token_file, CFS_WRITE | CFS_APPEND);
        if(fd_write != -1){
          n = cfs_write(fd_write, "\x00\x00\x00\x00\x00\x00\x00\x00" , 8);  
          n = cfs_write(fd_write, token->kid, 8);  
          n = cfs_write(fd_write, token->k, 16);  
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

  case CN_CBOR_INT:
    printf("NEGATIVE INT: %ld\n", cb->v.sint);
    if(cb->v.sint < 256){
      *claim = cb->v.sint;
      printf("CLM: %d\n",*claim);
    }
    else {
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
  char *bufend = NULL;
  char *buffer;
  char *buffer2;
  char *buffer3;
  char* nonce;
  char key[16] = {0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  cwt t;
  cwt *token = &t;
  unsigned char A_DATA[A_DATA_LEN];
  signed long claim = 0;
  printf("Received COSE message, last byte is %x\n", payload[112]);
  buffer = (char *) malloc(82);
  memcpy(buffer, &payload[31], 82);

  nonce = (char *) malloc(13);
  memcpy(nonce, &payload[16], 13);
  buffer2 = (char *) malloc(100);
  buffer3 = (char *) malloc(100);
  int u_len;
  u_len = dtls_decrypt(buffer, 82, buffer2, nonce, key, 16, A_DATA, A_DATA_LEN);
  int i;
  printf("%d bytes COSE decrypted\n", u_len);
  memcpy(buffer3, buffer2, u_len);
  cn_cbor *cb2 = cn_cbor_decode(buffer3, u_len CBOR_CONTEXT_PARAM, 0);
  if (cb2) {
    authenticate(&claim, token, cb2, buf, &bufend, 0);
    return 0;
  } else {
    printf("CBOR decode failed\n");
    return 1;
  }
}

