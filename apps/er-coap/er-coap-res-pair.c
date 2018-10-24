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

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const char *pairing_info = NULL;
  int len = REST.get_request_payload(request, (const uint8_t **)&pairing_info);
  printf("Len is %d\n", len);

  if(len > 0) {
    printf("Pairing info:");
    HEX_PRINTF(pairing_info, len);

    // We are reusing code to get token claims for pairing info. Pairing info will only
    // contain a kid and a key, as it comes in the CNF claim of a regular CWT token.
    cwt* key_info = parse_cbor_claims_into_cwt_struct(pairing_info, len);

    if(key_info != 0){
      printf("Obtained pairing key id and key\n");
      printf("Key id: ");
      HEX_PRINTF(key_info->kid, key_info->kid_len);
      printf("Key: ");
      HEX_PRINTF(key_info->key, KEY_LENGTH);

      if(store_token(key_info)) {
        REST.set_response_status(response, REST.status.CREATED);
        const char* success_message = "AS credentials added";
        REST.set_response_payload(response, success_message, strlen(success_message));
      }
      else {
        REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
        const char* failure_message = "Failed to store AS credentials";
        REST.set_response_payload(response, failure_message, strlen(failure_message));
      }

    } else {
      REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
      const char* failure_message = "Failed to parse AS credentials";
      REST.set_response_payload(response, failure_message, strlen(failure_message));
    }
  } else {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    const char* no_info_message = "No pairing info was received";
    REST.set_response_payload(response, no_info_message, strlen(no_info_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);

}

