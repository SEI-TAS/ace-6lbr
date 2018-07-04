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


static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_hello, NULL, NULL, res_get_handler, NULL, NULL);

res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  int n = 0;
  char const *const success_message = "HelloWorld!";
  char const *const failure_message = "HelloWorld!";

  if(n == 0){
    memcpy(buffer, success_message, strlen(success_message));
  } else {
    memcpy(buffer, failure_message, strlen(failure_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, sizeof(buffer));
}

