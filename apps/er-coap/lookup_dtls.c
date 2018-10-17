#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"


uint8_t* lookup_dtls_key(unsigned char *id, size_t id_len,
         unsigned char *result, size_t result_length){

  token_entry tok;

  if (read_token(id,id_len,&tok) > 0){
    printf("key here %s\n", tok.key);
    strncpy(result,tok.key,16);
    result_length = 17;
  }
  else {
    result_length = 0;
    printf("No DTLS PSK found\n");
  }



  return result_length;
}


