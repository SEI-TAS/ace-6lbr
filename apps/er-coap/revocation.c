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
#include "er-coap-dtls.h"

#include "cn-cbor/cn-cbor/cn-cbor.h"
#include "cbor-encode.h"
#include "key-token-store.h"
#include "resources.h"
#include "cwt.h"
#include "utils.h"


#ifdef USE_CBOR_CONTEXT
#define CBOR_CONTEXT_PARAM , NULL
#else
#define CBOR_CONTEXT_PARAM
#endif

#define IPV6_ADDRESS_LENGTH_BYTES 16
#define CHECK_WAIT_TIME_SECS 60
#define REQUEST_TIMEOUT_SECS 5

#define PROCESS_EVENT_INTROSPECTION_RESPONSE_PROCESSED 0x70
#define PROCESS_EVENT_DTLS_HANDSHAKE_FINISHED 0x71

#define INTROSPECTION_ENDPOINT "introspect"
#define INTROSPECTION_ACTIVE_KEY 29
#define AS_INTROSPECTION_PORT 5684

extern struct dtls_context_t* get_default_context_dtls();

static int get_as_ip_addr(uip_ipaddr_t* as_ip);
static void send_introspection_request(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip,
                                       const unsigned char* token_cti, int token_cti_len, authz_entry* curr_entry);
static int was_token_revoked(const unsigned char* cbor_result, int cbor_result_len);
void check_introspection_response(void* data, void* response);
static void delete_revoked_tokens();

/*-----------------------------------------------------------------------------------*/
// List of tokens to remove after each check iteration.
int num_tokens_to_remove = 0;
authz_entry* tokens_to_remove[MAX_AUTHZ_ENTRIES] = {0};

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

  printf("Starting revoked tokens checker!\n");
  static struct etimer et;
  static int timer_started = 0;
  static authz_entry_iterator iterator;
  static struct etimer timeout_timer;

  static struct dtls_context_t* ctx;
  static uip_ipaddr_t as_ip;
  static int has_pairing_as_ip = 0;

  ctx = get_default_context_dtls();
  while(1) {
     // Set or reset timer and check again in a while.
    if(timer_started == 0) {
      printf("Initial revocation check timer setup\n");
      etimer_set(&et, CHECK_WAIT_TIME_SECS * CLOCK_SECOND);
      timer_started = 1;
    }
    else {
      printf("Revocation check timer restarted.\n");
      etimer_restart(&et);
    }

    printf("Waiting till next revocation check cycle for %d seconds...\n", CHECK_WAIT_TIME_SECS);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    printf("Wait timer finished. Executing revocation check cycle.\n");

    if(has_pairing_as_ip == 0) {
      // Attempt to get the AS IP address.
      has_pairing_as_ip = get_as_ip_addr(&as_ip);
      if(has_pairing_as_ip == 0) {
        printf("Not paired to AS yet, skipping this check cycle.\n");
        continue;
      }
    }

    printf("Starting DTLS connection for this cycle.\n");
    int connection_started = start_dtls_connection(ctx, &as_ip, UIP_HTONS(AS_INTROSPECTION_PORT));
    if(connection_started == -1) {
      printf("Could not start DTLS connection! Skipping this check cycle.\n");
      continue;
    }

    // Wait till connection is established.
    static int handshake_timed_out = 0;
    printf("Checker process will wait until DTLS connection is finished...\n");
    etimer_set(&timeout_timer, REQUEST_TIMEOUT_SECS * CLOCK_SECOND);
    while(1) {
      PROCESS_WAIT_EVENT();
      if(ev == PROCESS_EVENT_DTLS_HANDSHAKE_FINISHED) {
        printf("Received DTLS connection completed event, checker thread will resume.\n");
        etimer_stop(&timeout_timer);
        break;
      }
      else if(ev == PROCESS_EVENT_TIMER && data == &timeout_timer) {
        printf("Timed out waiting for completion of DTLS handshake, skipping entry this cycle.\n");
        handshake_timed_out = 1;
        break;
      }
      else {
        printf("Unexpected event received (%d); ignoring.\n", ev);
      }
    }

    if(handshake_timed_out) {
      continue;
    }

    // Go over all tokens, ask if each is revoked, and remove it if so.
    printf("Starting token iterator.\n");
    iterator = authz_entry_iterator_initialize();
    printf("Looping over all tokens to find revoked ones.\n");
    static authz_entry* curr_entry = 0;
    while(1) {
      curr_entry = authz_entry_iterator_get_next(&iterator);
      if(curr_entry == 0) {
        break;
      }

      printf("Curr entry kid: ");
      HEX_PRINTF(curr_entry->kid, KEY_ID_LENGTH);
      printf("Curr entry claims len: %d\n", curr_entry->claims_len);

      if(curr_entry->claims_len == 0) {
        printf("Entry does not have information; ignoring it since it is not a valid token.\n");
        continue;
      }

      static cwt* token_info;
      token_info = parse_cbor_claims(curr_entry->claims, curr_entry->claims_len);
      if(!token_info) {
        printf("Entry does not have valid CBOR claims; ignoring it since it is not a valid token.\n");
        continue;
      }

      // Actually send the request.
      send_introspection_request(ctx, &as_ip, (const unsigned char *) token_info->cti,
                                 token_info->cti_len, curr_entry);

      // Wait until response is processed for this token.
      printf("Checker process will wait until introspection request is responded and processed.\n");
      authz_entry_iterator_close(&iterator);
      etimer_set(&timeout_timer, REQUEST_TIMEOUT_SECS * CLOCK_SECOND);
      while(1) {
        printf("Waiting...\n");
        PROCESS_WAIT_EVENT();
        if(ev == PROCESS_EVENT_INTROSPECTION_RESPONSE_PROCESSED) {
          printf("Received completion event, checker thread will resume.\n");
          etimer_stop(&timeout_timer);

          if((int) data == 0) {
            printf("Token will not be deleted, freeing local iterator entry.\n");
            free_authz_entry(curr_entry);
            free(curr_entry);
          }

          break;
        }
        else if(ev == PROCESS_EVENT_TIMER && data == &timeout_timer) {
          printf("Timed out waiting for completion of introspection response, skipping entry this cycle.\n");
          break;
        }
        else {
          printf("Unexpected event received (%d); ignoring.\n", ev);
        }
      }
      authz_entry_iterator_reopen(&iterator);
    }

    authz_entry_iterator_close(&iterator);
    printf("Finished executing check iteration.\n");

    printf("Closing DTLS connection.\n");
    close_current_dtls_connection();

    printf("Deleting revoked tokens.\n");
    delete_revoked_tokens();
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
// Used to start the process.
void start_revocation_checker() {
  process_start(&revocation_check, NULL);
}

/*---------------------------------------------------------------------------*/
// Notify main checker process that it can send messages.
void notify_connection_success() {
  process_post(&revocation_check, PROCESS_EVENT_DTLS_HANDSHAKE_FINISHED, 0);
}

/*---------------------------------------------------------------------------*/
static int get_as_ip_addr(uip_ipaddr_t* as_ip) {
  authz_entry as_pairing_entry = { 0 };
  printf("Trying to get AS IP from tokens file.\n");
  int has_pairing_as_ip = find_authz_entry((unsigned char*) RS_ID, strlen(RS_ID), &as_pairing_entry);
  if(has_pairing_as_ip == 0) {
    printf("Did not find AS IP in token file.\n");
    return 0;
  }
  else {
    printf("Got AS IP from tokens file: ");
    PRINTIP6ADDR(as_pairing_entry.claims);
    printf("\n");
    bytes_to_addr(as_pairing_entry.claims, as_ip);
    return 1;
  }
}

/*---------------------------------------------------------------------------*/
// Sends an introspection request, and returns the result.
static void send_introspection_request(struct dtls_context_t* ctx, uip_ipaddr_t* as_ip,
                                       const unsigned char* token_cti, int token_cti_len, authz_entry* curr_entry) {
  printf("Preparing introspection request.\n");

  // Prepare payload.
  printf("Encoding payload.\n");
  unsigned char* token_as_byte_string;
  int token_as_byte_string_len = encode_bytes_to_cbor(token_cti, token_cti_len, &token_as_byte_string);
  printf("Token as BS: ");
  HEX_PRINTF(token_as_byte_string, token_as_byte_string_len);
  unsigned char* payload;
  int payload_len = encode_single_pair_map_to_cbor(TOKEN_KEY, token_as_byte_string, token_as_byte_string_len, &payload);
  printf("Encoded payload: ");
  HEX_PRINTF(payload, payload_len);
  printf("\n");

  printf("Sending introspection request message.\n");
  send_new_dtls_message(ctx, as_ip, UIP_HTONS(AS_INTROSPECTION_PORT), INTROSPECTION_ENDPOINT,
                        payload, payload_len, check_introspection_response, curr_entry);
  free(payload);
  free(token_as_byte_string);
}

/*---------------------------------------------------------------------------*/
// Callback that will be called from Erbium engine when processing transaction reply.
void check_introspection_response(void* data, void* response) {
  // Cast the original data we need to process this, and the CBOR in the response.
  printf("Received introspection response!\n");
  authz_entry* curr_entry = (authz_entry*) data;
  unsigned char* cbor_result = ((coap_packet_t*) response)->payload;
  int cbor_result_len = ((coap_packet_t*) response)->payload_len;
  printf("CBOR response, len %d: ", cbor_result_len);
  HEX_PRINTF(cbor_result, cbor_result_len);

  // Check the response.
  int token_was_revoked = was_token_revoked(cbor_result, cbor_result_len);

  // Add token to removal list if revoked, or free its temp memory if not.
  if(token_was_revoked) {
    printf("Adding token to removal list.\n");
    tokens_to_remove[num_tokens_to_remove++] = curr_entry;
  }
  else {
    printf("Token is active or could not be checked; not removing.\n");
  }

  // Notify main checker process that it can move on into the next token.
  printf("Notifying that we finished processing introspection response.\n");
  process_post(&revocation_check, PROCESS_EVENT_INTROSPECTION_RESPONSE_PROCESSED, (void *) (uintptr_t) token_was_revoked);
}

/*---------------------------------------------------------------------------*/
// Parse revocation response. We assume we have a simple map as response (as specified in the standard), and the
// only key-pair is "active" with a CBOR value of TRUE or FALSE.
static int was_token_revoked(const unsigned char* cbor_result, int cbor_result_len) {
  int token_was_revoked = 0;
  if(cbor_result_len > 0) {
    cn_cbor* map_object = cn_cbor_decode(cbor_result, cbor_result_len CBOR_CONTEXT_PARAM, 0);
    if(map_object->type == CN_CBOR_MAP) {
      printf("Map found in response!\n");
      cn_cbor* pair_key = map_object->first_child;
      if(pair_key->v.uint == INTROSPECTION_ACTIVE_KEY) {
        printf("'Active' key found in response!\n");
        cn_cbor* active_value = pair_key->next;

        if(active_value == 0) {
          printf("Value for key not found!");
        }
        else if(active_value->type == CN_CBOR_FALSE) {
          printf("Token has been marked as not active.\n");
          token_was_revoked = 1;
        }
        else {
          printf("Token is still active!\n");
        }
      }
      else {
        printf("Response did not have 'active' key as the first key in the map; stopped processing.\n");
      }
    }
    else {
      printf("Response was not a map.\n");
    }

    free(map_object);
  }

  return token_was_revoked;
}

//---------------------------------------------------------------------------
static
void delete_revoked_tokens() {
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

    num_tokens_to_remove = 0;
  }
  else {
    printf("No tokens to remove.\n");
  }
}
