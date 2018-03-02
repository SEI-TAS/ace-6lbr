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
#include "./cwt.h"

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_authz_info, NULL, NULL, res_post_handler, NULL, NULL);

res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  uint8_t *token = NULL;
  size_t len;
  int n;
  char const *const success_message = "ACE credentials added";
  char const *const failure_message = "Failed to add ACE credentials";

  len = REST.get_request_payload(request, (const uint8_t **)&token);
  /* n = read_cose(token, len); */
  if(n == 0){
    memcpy(buffer, success_message, strlen(success_message));
  } else {
    memcpy(buffer, failure_message, strlen(failure_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, sizeof(buffer));
}
