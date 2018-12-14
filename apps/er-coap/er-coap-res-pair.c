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
#include "cfs/cfs.h"

#include "cwt.h"
#include "key-token-store.h"
#include "cbor-encode.h"
#include "utils.h"

#include "resources.h"

#define CBOR_DEVICE_ID_KEY 3
#define CBOR_DEVICE_INFO_KEY 4

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
void set_cbor_error_response(void* response, unsigned int response_code, int error_code, const char* error_desc);

RESOURCE(res_pair, NULL, NULL, res_post_handler, NULL, NULL);

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const unsigned char *pairing_info = NULL;
  int len = REST.get_request_payload(request, (const uint8_t **)&pairing_info);
  printf("Len is %d\n", len);

  if(len > 0) {
    printf("Pairing info:");
    HEX_PRINTF(pairing_info, len);

    // We are reusing code to get token claims for pairing info. Pairing info will only
    // contain a kid and a key, as it comes in the CNF claim of a regular CWT token.
    cwt* key_info = parse_cbor_claims(pairing_info, len);

    if(key_info != 0){
      printf("Obtained pairing AS id and key\n");
      printf("AS id: ");
      HEX_PRINTF(key_info->kid, key_info->kid_len);
      printf("Key: ");
      HEX_PRINTF(key_info->key, KEY_LENGTH);

      // We will ignore the AS id, since our id is what the AS will use as the Key ID for this key.
      printf("Will store key with our id: %s\n", RS_ID);
      authz_entry* authz_info = create_authz_entry((unsigned char*) RS_ID, strlen(RS_ID), key_info->key, 0, 0, 0);
      if(store_authz_entry(authz_info)) {
        // We have to respond with our key and scopes, encoded in CBOR.
        printf("Encoding response with device id and scopes.\n");
        unsigned char* cbor_bytes = 0;
        int cbor_bytes_len = encode_map_to_cbor(CBOR_DEVICE_ID_KEY, 0, RS_ID,
                                                CBOR_DEVICE_INFO_KEY, 0, SCOPES, &cbor_bytes);

        // Set the CBOR data in the response.
        printf("Sending reply.\n");
        REST.set_response_status(response, REST.status.CREATED);
        REST.set_response_payload(response, cbor_bytes, cbor_bytes_len);
      }
      else {
        const char* failure_message = "Failed to store AS credentials";
        set_cbor_error_response(response, REST.status.INTERNAL_SERVER_ERROR, CBOR_ERROR_CODE_INVALID_REQUEST, failure_message);
      }

    } else {
      const char* failure_message = "Failed to parse AS credentials";
      set_cbor_error_response(response, REST.status.BAD_REQUEST, CBOR_ERROR_CODE_INVALID_REQUEST, failure_message);
    }
  } else {
    const char* failure_message = "No pairing info was received";
    set_cbor_error_response(response, REST.status.BAD_REQUEST, CBOR_ERROR_CODE_INVALID_REQUEST, failure_message);
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
}

// Sets the response params for a given CBOR error.
void set_cbor_error_response(void* response, unsigned int response_code, int error_code, const char* error_desc) {
  REST.set_response_status(response, response_code);
  unsigned char* cbor_bytes = 0;
  int cbor_bytes_len = encode_map_to_cbor(CBOR_ERROR_CODE_KEY, error_code, 0,
                                          CBOR_ERROR_DESC_KEY, 0, error_desc, &cbor_bytes);
  REST.set_response_payload(response, cbor_bytes, cbor_bytes_len);
}

