#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"


int lookup_dtls_key(unsigned char *id, size_t id_len,
         unsigned char *result, size_t result_length){

  token_entry tok;

  int key_length = 0;
  if (read_token(id,id_len,&tok) > 0){
    printf("key here %s\n", tok.key);
    strncpy(result,tok.key,16);
    key_length = 16;
  }
  else {
    printf("No DTLS PSK found\n");
  }

  return key_length;
}


