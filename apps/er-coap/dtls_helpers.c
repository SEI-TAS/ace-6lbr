#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dtls.h"
#include "peer.h"
#include "dtls_crypto.h"

#include "cwt.h"
#include "dtls_helpers.h"
#include "key-token-store.h"
#include "utils.h"

// Global variables to store identity.
static unsigned char* current_key_id = 0;
static int current_key_id_length;

int lookup_dtls_key(const unsigned char * const id, size_t id_len,
         unsigned char * const result, size_t result_length){

  token_entry tok;
  int key_length = 0;
  if (find_token_entry(id, id_len, &tok) > 0){
    printf("Key found!\n");
    if(result_length < KEY_LENGTH) {
      printf("Buffer is too small for key!");
    }
    else {
      memcpy(result, tok.key, KEY_LENGTH);
      key_length = KEY_LENGTH;

      if(current_key_id) {
        free(current_key_id);
      }
      current_key_id_length = id_len;
      current_key_id = (unsigned char*) malloc(id_len);
      memcpy(current_key_id, id, id_len);
    }
  }
  else {
    printf("No DTLS PSK found\n");
  }

  return key_length;
}

// Gets the identity of the current connection. Tries context, gets last global variable otherwise.
int find_dtls_context_key_id(context_t* ctx, unsigned char** identity) {
    // Identity is in ctx->peers[0?]->handshake_parameters->keyx.psk.identity
    (*identity) = 0;
    int id_length = 0;
    dtls_peer_t* curr_peer = ctx->peers;
    while(curr_peer) {
      printf("Checking peer info: Peer role: %d; connection state: %d\n", ctx->peers->role, ctx->peers->state);
      dtls_handshake_parameters_t* params = ctx->peers->handshake_params;
      if(params == 0) {
        printf("No handshake params found! Trying next peer.\n");
        curr_peer = curr_peer->next;
        continue;
      }
      printf("Identity length: %d\n", params->keyx.psk.id_length);
      if(params->keyx.psk.id_length > 0) {
        printf("Identity: \n");
        HEX_PRINTF(params->keyx.psk.identity, params->keyx.psk.id_length);
        (*identity) = params->keyx.psk.identity;
        id_length = params->keyx.psk.id_length;
      }

      curr_peer = curr_peer->next;
    }

    if(id_length == 0) {
      printf("Context info not found. Using global variable.\n");
      printf("Last stored key id: ");
      HEX_PRINTF(current_key_id, current_key_id_length);
      (*identity) = current_key_id;
      id_length = current_key_id_length;
    }

    return id_length;
}
