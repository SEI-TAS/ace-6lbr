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

RESOURCE(res_lock, NULL, NULL, res_post_handler, NULL, NULL);

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  uint8_t *aes_token = NULL;
  size_t len;
  char *token_file = "tokens";
  int fd_write, n;
  char const *const success_message = "AS credentials added";
  char const *const failure_message = "Failed to add AS credentials";

  len = REST.get_request_payload(request, (const uint8_t **)&aes_token);

  fd_write = cfs_open(token_file, CFS_WRITE);
  if(fd_write != -1){
    n = cfs_write(fd_write, "Authentication01", 16);
    n = cfs_write(fd_write, ":", 1);
    n = cfs_write(fd_write, aes_token, len);
    cfs_close(fd_write);
  }

  if(n == 0){
    memcpy(buffer, success_message, strlen(success_message));
  } else {
    memcpy(buffer, failure_message, strlen(failure_message));
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, sizeof(buffer));
}

