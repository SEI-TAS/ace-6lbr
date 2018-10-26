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

#include "cbor-encode.h"
#include "utils.h"

static int lock_status = 0;

static void res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_lock, NULL, res_get_handler, NULL, res_put_handler, NULL);

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  printf("Requesting Lock resource\n");
  printf("Lock is currently: %d\n", lock_status);
  unsigned char result[1];
  result[0] = CBOR_PRFIX_INT | lock_status; // Encode as CBOR INT

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, result, 1);
}

static void res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  printf("Putting Lock resource\n");
  printf("Lock is currently: %d\n", lock_status);

  const unsigned char* lock_info = NULL;
  int payload_len = REST.get_request_payload(request, (const uint8_t **)&lock_info);
  printf("Payload length: %d\n", payload_len);
  printf("Payload: ");
  HEX_PRINTF(lock_info, payload_len)
  if(payload_len > 0) {
    // Payload is 0 or 1 but comes as text. First byte is text header, second is digit as ASCII. -'0' turns to int.
    int new_lock_value = lock_info[1] - '0';
    printf("Received lock value: %d\n", new_lock_value);
    lock_status = new_lock_value;
    printf("Lock is now: %d\n", lock_status);
  }

  unsigned char result[1];
  result[0] = CBOR_PRFIX_INT | lock_status; // Encode as CBOR INT
  printf("Sending back: %d\n", (int) result[0]);

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, result, 1);
}

