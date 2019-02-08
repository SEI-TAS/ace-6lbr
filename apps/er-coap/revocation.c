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
#define CHECK_WAIT_TIME_SECS 30
#define PROCESS_EVENT_INTRO_DONE 0x70

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
  int timer_started = 0;
  struct dtls_context_t* ctx = get_default_context_dtls();
  uip_ipaddr_t as_ip;
  int has_pairing_as_ip = 0;

  while(1) {
    printf("Executing check iteration.\n");

    if(has_pairing_as_ip == 0) {
      // Attempt to get the AS IP address.
      has_pairing_as_ip = get_as_ip_addr(&as_ip);
    }

    if(has_pairing_as_ip == 0) {
      printf("RS not paired, skipping this check iteration.\n");
    }
    else {
      authz_entry_iterator iterator = authz_entry_iterator_initialize();

      // Go over all tokens, ask if each is revoked, and remove it if so.
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
            send_introspection_request(ctx, &as_ip, (const unsigned char *) token_info->cti,
                                       token_info->cti_len, curr_entry);

            // Wait until response is processed for this token.
            printf("Checker process will wait until introspection request is responded and processed..\n");
            PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_INTRO_DONE);
          }
        }
        else {
          printf("Entry does not have information; ignoring it.\n");
        }

        curr_entry = authz_entry_iterator_get_next(&iterator);
      }

      authz_entry_iterator_finish(iterator);
      printf("Finished executing check iteration.\n");

      delete_revoked_tokens();
    }

     // Set or reset timer and check again in a while.
    if(timer_started == 0) {
      printf("Initial timer setup\n");
      etimer_set(&et, CHECK_WAIT_TIME_SECS * CLOCK_SECOND);
      timer_started = 1;
    }
    else {
      printf("Timer reset.\n");
      etimer_reset(&et);
    }

    printf("Waiting till next cycle for %d seconds...\n", CHECK_WAIT_TIME_SECS);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
// Used to start the process.
void start_revocation_checker() {
  process_start(&revocation_check, NULL);
}

/*---------------------------------------------------------------------------*/
static int get_as_ip_addr(uip_ipaddr_t* as_ip) {
  authz_entry as_pairing_entry = { 0 };
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

  printf("Sending (queuing) introspection request message.\n");
  send_new_dtls_message(ctx, as_ip, UIP_HTONS(AS_INTROSPECTION_PORT), INTROSPECTION_ENDPOINT,
                        payload, payload_len, check_introspection_response, curr_entry);

  printf("Introspection request queued.\n");
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
    printf("Token is active, not removing.\n");
    free_authz_entry(curr_entry);
    free(curr_entry);
  }

  // Notify main checker process that it can move on into the next token.
  process_post(&revocation_check, PROCESS_EVENT_INTRO_DONE, 0);
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
        printf("Active key found in response!\n");
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
        printf("Response did not have 'active' key first.\n");
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

    num_tokens_to_remove = 0
  }
  else {
    printf("No tokens to remove.\n");
  }
}
