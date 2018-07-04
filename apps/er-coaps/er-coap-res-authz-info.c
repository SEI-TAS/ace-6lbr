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
  const uint8_t *token = NULL;
  size_t len;
  int n;
  char const *const success_message = "ACE credentials added";
  char const *const failure_message = "Failed to add ACE credentials";

  len = REST.get_request_payload(request, (const uint8_t **)&token);
  printf("Len is %d\n", len);
  printf("Token:");
  int i;
  for (i=0; i<80; i++){
    printf(" %x",token[i]);
  }
  printf("\n");
  n = read_cbor(token, 79); 

  char *token_file = "tokens";
  int fd_read, o;

  fd_read = cfs_open(token_file, CFS_READ);
  if (fd_read != -1){
    o = cfs_read(fd_read, buffer, 64);
    cfs_close(fd_read);
  } else {
    memcpy(buffer, failure_message, strlen(failure_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, strlen(buffer));
}
