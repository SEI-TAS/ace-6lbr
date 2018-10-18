/*
 * Endpoint called /pair for pairing an ACE RS with an AS
 * on 6lbr (Contiki)
 *
 * Dan Klinedinst, Software Engineering Institute, Carnegie Mellon University
*/


#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"
#include "cfs/cfs.h"
#include "./cwt.h"


static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_pair, NULL, NULL, res_post_handler, NULL, NULL);

res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const uint8_t *aes_token = NULL;
  char* AS_key;
  size_t len;
  char *token_file = "tokens";
  int fd_write, n;
  char const *const success_message = "AS credentials added";
  char const *const failure_message = "Failed to add AS credentials";

  len = REST.get_request_payload(request, (const uint8_t **)&aes_token);
  printf("Len is %d\n", len);
  printf("Token:");
  int i;
  for (i=0; i<len; i++){
    printf(" %x",aes_token[i]);
  }
  printf("\n");
  n = read_cbor(aes_token, len);

  if(n == 0){
    memcpy(buffer, success_message, strlen(success_message));
  } else {
    memcpy(buffer, failure_message, strlen(failure_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, strlen(buffer));
}

