/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
/*
 * Endpoint called /pair for pairing an ACE RS with an AS
 * on 6lbr (Contiki)
 *
 * Dan Klinedinst, Software Engineering Institute, Carnegie Mellon University
*/


#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"

#include "resources.h"
#include "cbor-encode.h"
#include "utils.h"

static int lock_status = 0;

void return_lock_value();

static void res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_lock, NULL, res_get_handler, NULL, res_put_handler, NULL);

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  printf("Getting Lock resource\n");
  printf("Lock is: %d\n", lock_status);
  return_lock_value(response);
}

static void res_put_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  printf("Putting Lock resource\n");
  printf("Lock is initially: %d\n", lock_status);

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

  return_lock_value(response);
}

void return_lock_value(void* response) {
  char lock_as_string[2];
  snprintf(lock_as_string, 2, "%d", lock_status);
  unsigned char* encoded_result;
  int encoded_len = encode_string_to_cbor(lock_as_string, strlen(lock_as_string), &encoded_result);

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, encoded_result, encoded_len);
}

// Returns a structure with the information about scope and methods for this resource.
resource_info* get_resource_info_lock() {
  scope_info* scope1 = (scope_info*) malloc(sizeof(scope_info));
  memset(scope1, 0, sizeof(scope_info));
  scope1->name = "rw_Lock";
  scope1->methods[POS_GET] = 1;
  scope1->methods[POS_POST] = 1;

  scope_info* scope2 = (scope_info*) malloc(sizeof(scope_info));
  memset(scope2, 0, sizeof(scope_info));
  scope2->name = "r_Lock";
  scope2->methods[POS_GET] = 1;

  resource_info* resource = (resource_info*) malloc(sizeof(resource_info));
  resource->name = "ace/lock";
  resource->scope_info_list_len = 2;
  resource->scope_info_list = (scope_info**) malloc(sizeof(scope_info*) * resource->scope_info_list_len);
  resource->scope_info_list[0] = scope1;
  resource->scope_info_list[1] = scope2;

  return resource;
}

