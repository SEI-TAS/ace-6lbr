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
#include "er-coap-constants.h"
#include "./cwt.h"

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_authz_info, NULL, NULL, res_post_handler, NULL, NULL);

res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  const uint8_t *token = NULL;
  int n;
  char const *const success_message = "ACE credentials added";
  char const *const no_token_message = "No token was received";
  char const *const failure_message = "Failed to add ACE credentials";
  char* response_buffer;

  size_t token_len = REST.get_request_payload(request, (const uint8_t **)&token);
  printf("token_len is %d\n", token_len);

  if(token_len > 0) {
    printf("Token:");
    int i;
    for (i=0; i<token_len; i++){
      printf(" %x",token[i]);
    }
    printf("\n");
    n = read_cbor(token, token_len);

    char *token_file = "tokens";
    int fd_read;
    int bytes_read;

    fd_read = cfs_open(token_file, CFS_READ);
    if (fd_read != -1){
      bytes_read = cfs_read(fd_read, buffer, 128);
      cfs_close(fd_read);
      printf("File:");
      int i;
      for (i=0; i<128; i++){
        printf(" %x",buffer[i]);
      }
      printf("\n");
    } else {
      REST.set_response_status(response, INTERNAL_SERVER_ERROR_5_00);
      memcpy(response_buffer, failure_message, strlen(failure_message));
    }

    REST.set_response_status(response, CREATED_2_01);
  }
  else {
    REST.set_response_status(response, BAD_REQUEST_4_00);
    memcpy(response_buffer, no_token_message, strlen(no_token_message));
  }

  REST.set_header_content_type(response, REST.type.APPLICATION_OCTET_STREAM);
  REST.set_response_payload(response, response_buffer, strlen(response_buffer));
}
