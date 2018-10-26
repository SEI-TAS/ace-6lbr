/*
 * A simeple authz-info endpoint for ACE running on Erbium COAP server
 * on 6lbr (Contiki)
 *
 * Dan Klinedinst, Software Engineering Institute, Carnegie Mellon University
*/


#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"
#include "cfs/cfs.h"
#include "cwt.h"
#include "utils.h"

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_authz_info, NULL, NULL, res_post_handler, NULL, NULL);

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const uint8_t *cbor_token = NULL;

  size_t token_len = REST.get_request_payload(request, (const uint8_t **)&cbor_token);
  printf("token_len is %ld\n", token_len);

  if(token_len > 0) {
    printf("CBOR token: ");
    HEX_PRINTF(cbor_token, token_len)

    cwt* token = parse_cwt_token(cbor_token, token_len);
    if(token == 0) {
      REST.set_response_status(response, REST.status.BAD_REQUEST);
      const char* error_message = "Error parsing CWT token";
      REST.set_response_payload(response, error_message, strlen(error_message));
    }
    else {
      if(store_token(token) == 1) {
        printf("Stored default pairing key in tokens file.\n");
        REST.set_response_status(response, REST.status.CREATED);
        const char* success_message = "ACE credentials added";
        REST.set_response_payload(response, success_message, strlen(success_message));
      } else {
        REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
        const char* error_message = "Failed to add ACE credentials, could not open tokens file";
        REST.set_response_payload(response, error_message, strlen(error_message));
      }
    }
  }
  else {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    const char* no_token_message = "No token was received";
    REST.set_response_payload(response, no_token_message, strlen(no_token_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
}
