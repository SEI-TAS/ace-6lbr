/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#include "contiki.h"
#include "contiki-lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfs/cfs.h"
#include "sys/etimer.h"
#include "er-coap-transactions.h"

#include "cn-cbor/cn-cbor/cn-cbor.h"
#include "cbor-encode.h"
#include "key-token-store.h"
#include "resources.h"
#include "cwt.h"
#include "utils.h"

// 0. DONE! Figure out how to store the IP of each AS associated with the token. When pairing?
// 1. DONE! Timed process or sleep.
// 2. CoAP client to send request.
// 3. DONE! Loop over all tokens.
// 4. Parse revocation response.
// 5. DONE! Remove revoked tokens froms storage.

#ifdef USE_CBOR_CONTEXT
#define CBOR_CONTEXT_PARAM , NULL
#else
#define CBOR_CONTEXT_PARAM
#endif

#define IPV6_ADDRESS_LENGTH_BYTES 16
#define CHECK_WAIT_TIME_SECS 20
#define INTROSPECTION_ENDPOINT "introspect"
#define INTROSPECTION_ACTIVE_KEY "active"
#define AS_INTROSPECTION_PORT 5684
#define MAX_PAYLOAD_LEN 300

extern struct dtls_context_t* get_default_context_dtls();

static void check_revoked_tokens(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip);
static void send_introspection_request(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip,
                                       const unsigned char* token_cti, int token_cti_len, authz_entry* curr_entry);
static int was_token_revoked(const unsigned char* cbor_result, int cbor_result_len);
void check_introspection_response(void* data, void* response);

/*-----------------------------------------------------------------------------------*/
static void
bytes_to_addr(unsigned char* bytes, uip_ipaddr_t* addr)
{
  int i = 0;
  for(i = 0; i < IPV6_ADDRESS_LENGTH_BYTES; i++) {
    ((uint8_t*)addr)[i] = bytes[i];
  }
}

/*---------------------------------------------------------------------------*/
PROCESS(revocation_check, "Revoked Tokens Checker");
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(revocation_check, ev, data)
{
  PROCESS_BEGIN();

  printf("Executing revoked tokens checker!\n");

  static struct etimer et;
  int timer_started = 0;

  struct dtls_context_t* ctx = get_default_context_dtls();

  // First get the AS IP.
  authz_entry as_pairing_entry = { 0 };
  int result = find_authz_entry((unsigned char*) RS_ID, strlen(RS_ID), &as_pairing_entry);
  if(result == 0) {
    printf("Could not get AS IP from token file.\n");
  }
  else {
    printf("Got AS IP from tokens file: ");
    PRINTIP6ADDR(as_pairing_entry.claims);
    printf("\n");

    uip_ipaddr_t as_ip;
    bytes_to_addr(as_pairing_entry.claims, &as_ip);

    while(1) {
      check_revoked_tokens(ctx, &as_ip);

       // Set or reset timer and check again in a while.
      if(timer_started == 0) {
        etimer_set(&et, CHECK_WAIT_TIME_SECS * CLOCK_SECOND);
        timer_started = 1;
      }
      else {
        etimer_reset(&et);
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
// Used to start the process.
void start_revocation_checker() {
  process_start(&revocation_check, NULL);
}

/*---------------------------------------------------------------------------*/
// Main function to check for revoked tokens.
static void check_revoked_tokens(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip) {
  printf("Executing check iteration.\n");

  authz_entry_iterator iterator = authz_entry_iterator_initialize();

  // Add all revoked tokens to a list (removing them all together later is more efficient).
  printf("Looping over all tokens to find revoked ones.\n");
  authz_entry* curr_entry = authz_entry_iterator_get_next(&iterator);
  while(curr_entry != 0) {
    printf("Curr entry kid: ");
    HEX_PRINTF(curr_entry->kid, KEY_ID_LENGTH);

    printf("Curr entry claims len: %d\n", curr_entry->claims_len);
    if(curr_entry->claims_len > 0) {
      // Send introspection request; responses will be handled asynchronously.
      cwt* token_info = parse_cbor_claims(curr_entry->claims, curr_entry->claims_len);
      if(!token_info) {
        printf("Entry does not have valid CBOR claims; ignoring it.\n");
      }
      else {
        send_introspection_request(ctx, as_ip, (const unsigned char *) token_info->cti,
                                 token_info->cti_len, curr_entry);
      }
    }

    curr_entry = authz_entry_iterator_get_next(&iterator);
  }

  authz_entry_iterator_finish(iterator);

  printf("Finished executing check iteration.\n");
}

/*---------------------------------------------------------------------------*/
// Sends an introspection request, and returns the result.
static void send_introspection_request(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip,
                                       const unsigned char* token_cti, int token_cti_len, authz_entry* curr_entry) {

  printf("Sending introspection request message.\n");

  // Init message.
  static coap_packet_t message[1];
  coap_init_message(message, COAP_TYPE_CON, COAP_POST, coap_get_mid());
  coap_set_header_uri_path(message, INTROSPECTION_ENDPOINT);

  // Prepare payload.
  unsigned char* payload;
  int payload_len = encode_single_pair_to_cbor_map(TOKEN_KEY, token_cti, token_cti_len, &payload);
  coap_set_payload(message, payload, payload_len);

  // Set up a transaction so we can process the result when returned.
  printf("Preparing transaction.\n");
  static coap_transaction_t *transaction = NULL;
  transaction = coap_new_transaction(message->mid, as_ip, AS_INTROSPECTION_PORT, 1);
  coap_set_transaction_context_dtls(transaction, ctx);
  transaction->callback = check_introspection_response;
  transaction->callback_data = curr_entry;

  // Serialize the message.
  printf("Serializing message.\n");
  uint8_t serialized_message[MAX_PAYLOAD_LEN];
  memset(serialized_message, 0, MAX_PAYLOAD_LEN);
  int serialized_message_len = coap_serialize_message(message, &serialized_message);

  // Send the message.
  printf("Sending message.\n");
  coap_send_message_dtls(ctx, as_ip, AS_INTROSPECTION_PORT, serialized_message, serialized_message_len);
  printf("Introspection request sent.\n");
  free(payload);
}

/*---------------------------------------------------------------------------*/
void check_introspection_response(void* data, void* response) {
  // Cast the original data we need to process this, and the CBOR in the response.
  authz_entry* curr_entry = (authz_entry*) data;
  unsigned char* cbor_result = ((coap_packet_t*) response)->payload;
  int cbor_result_len = ((coap_packet_t*) response)->payload_len;

  // Check the response.
  int token_was_revoked = was_token_revoked(cbor_result, cbor_result_len);

  // Add token to removal list if revoked, or free its temp memory if not.
  if(token_was_revoked) {
    /*printf("Adding token to removal list.\n");
    tokens_to_remove[num_tokens_to_remove++] = curr_entry;*/

    int num_tokens_to_remove = 0;
    authz_entry* tokens_to_remove[MAX_AUTHZ_ENTRIES] = {0};

    tokens_to_remove[num_tokens_to_remove++] = curr_entry;
    remove_authz_entries(tokens_to_remove, num_tokens_to_remove);
  }
  else {
    free_authz_entry(curr_entry);
    free(curr_entry);
  }
}

/*
int num_tokens_to_remove = 0;
authz_entry* tokens_to_remove[MAX_AUTHZ_ENTRIES] = {0};*/

/*---------------------------------------------------------------------------
void delete_revoked_tokens()
  // TODO: method to delete several at once, may be used later.

  // Remove all revoked tokens, and then free the memory for their temp structs.
  printf("Total tokens to remove: %d\n", num_tokens_to_remove);
  if(num_tokens_to_remove > 0) {
    int num_removed = remove_authz_entries(tokens_to_remove, num_tokens_to_remove);
    printf("Removed %d tokens.\n", num_removed);

    int i = 0;
    for(i = 0; i < num_tokens_to_remove; i++) {
      authz_entry* curr_entry = tokens_to_remove[i];
      free_authz_entry(curr_entry);
      free(curr_entry);
    }

    num_tokens_to_remove = 0
  }
  else {
    printf("No tokens to remove.\n");
  }

}*/

/*---------------------------------------------------------------------------*/
// Parse revocation response. We assume we have a simple map as response (as specified in the standard), and the
// only key-pair is "active" with a CBOR value of TRUE or FALSE.
static int was_token_revoked(const unsigned char* cbor_result, int cbor_result_len) {
  int token_was_revoked = 0;
  if(cbor_result_len > 0) {
    cn_cbor* cbor_object = cn_cbor_decode(cbor_result, cbor_result_len CBOR_CONTEXT_PARAM, 0);
    if(cbor_object->type == CN_CBOR_MAP) {
      cn_cbor* pair_key = cbor_object->first_child;
      if((pair_key->type == CN_CBOR_TEXT) && (memcmp(pair_key->v.str, INTROSPECTION_ACTIVE_KEY, strlen(INTROSPECTION_ACTIVE_KEY)) == 0)) {
        cn_cbor* active_value = cbor_object->next;

        if(active_value->type == CN_CBOR_FALSE) {
          printf("Token has been marked as not active.");
          token_was_revoked = 1;
        }
      }
      else {
        printf("Response did not have 'active' key first.");
      }
    }
    else {
      printf("Response was not a map.");
    }

    free(cbor_object);
  }

  return token_was_revoked;
}