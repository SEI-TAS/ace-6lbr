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
#include "key-token-store.h"
#include "utils.h"

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_authz_info, NULL, NULL, res_post_handler, NULL, NULL);

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const uint8_t *cbor_token = NULL;

  printf("Received new token to be stored.\n");
  size_t token_len = REST.get_request_payload(request, (const uint8_t **)&cbor_token);
  printf("token_len is %ld\n", token_len);
  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);

  if(token_len == 0) {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    const char* no_token_message = "No token was received";
    REST.set_response_payload(response, no_token_message, strlen(no_token_message));
    return;
  }

  printf("CBOR token: ");
  HEX_PRINTF(cbor_token, token_len)
  cwt* token = parse_cwt_token(cbor_token, token_len);
  if(token == 0) {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    const char* error_message = "Error parsing CWT token";
    REST.set_response_payload(response, error_message, strlen(error_message));
    return;
  }

  // Validate claims in token.
  char* error;
  if(validate_claims(token, &error) == 0) {
    REST.set_response_status(response, REST.status.BAD_REQUEST);
    REST.set_response_payload(response, error, strlen(error));
    return;
  }

  // If token is valid, store.
  if(store_token(token) == 0) {
    REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
    const char* error_message = "Failed to store token.";
    REST.set_response_payload(response, error_message, strlen(error_message));
  }

  printf("Stored token in tokens file.\n");
  REST.set_response_status(response, REST.status.CREATED);
  const char* success_message = "Token was validated and stored.";
  REST.set_response_payload(response, success_message, strlen(success_message));
}
