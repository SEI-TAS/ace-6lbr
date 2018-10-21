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
  char* AS_key;
  char *token_file = "tokens";
  int fd_write;

  const uint8_t *pairing_info = NULL;
  int len = REST.get_request_payload(request, (const uint8_t **)&pairing_info);
  printf("Len is %d\n", len);

  if(len > 0) {
    printf("Pairing info:");
    int i;
    for (i=0; i<len; i++){
      printf(" %x",pairing_info[i]);
    }
    printf("\n");

    int n = read_cbor(pairing_info, len);
    if(n == 0){
      REST.set_response_status(response, REST.status.CREATED);
      const char* success_message = "AS credentials added";
      REST.set_response_payload(response, success_message, strlen(success_message));
    } else {
      REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
      const char* failure_message = "Failed to add AS credentials";
      REST.set_response_payload(response, failure_message, strlen(failure_message));
    }
  } else {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    const char* no_info_message = "No pairing info was received";
    REST.set_response_payload(response, no_info_message, strlen(no_info_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);

}

