#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"

int lookup_dtls_key(const unsigned char * const id, size_t id_len,
         unsigned char * const result, size_t result_length){

  token_entry tok;
  int key_length = 0;
  if (find_token_entry(id, id_len, &tok) > 0){
    printf("Key found!\n");
    if(result_length < KEY_LENGTH) {
      printf("Buffer is too small for key!");
    }
    else {
      memcpy(result, tok.key, KEY_LENGTH);
      key_length = KEY_LENGTH;
    }
  }
  else {
    printf("No DTLS PSK found\n");
  }

  return key_length;
}


