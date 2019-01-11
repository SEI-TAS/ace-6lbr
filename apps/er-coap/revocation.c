/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contiki.h"
#include "cfs/cfs.h"
#include "sys/etimer.h"

#include "key-token-store.h"
#include "resources.h"
#include "cwt.h"
#include "utils.h"

// 0. DONE! Figure out how to store the IP of each AS associated with the token. When pairing?
// 1. Timed process or sleep.
// 2. CoAP client to send request.
// 3. DONE! Loop over all tokens.
// 4. Parse revocation response.
// 5. DONE! Remove revoked tokens froms storage.

#define CHECK_WAIT_TIME_SECS 20

void check_revoked_tokens();

/*---------------------------------------------------------------------------*/
PROCESS(revocation_check, "Revoked Tokens Checker");
AUTOSTART_PROCESSES(&revocation_check);
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(acers, ev, data)
{
  PROCESS_BEGIN();

  check_revoked_tokens();

  PROCESS_END();
}

// Main function to check for revoked tokens.
void check_revoked_tokens() {
  static struct etimer et = 0;
  printf("Executing revoked tokens checker!\n");

  // First get the AS IP.
  authz_entry as_pairing_entry = { 0 };
  int result = find_authz_entry((unsigned char*) RS_ID, strlen(RS_ID), &as_pairing_entry);
  if(result == 0) {
    printf("Could not get AS IP from token file.");
    return;
  }

  printf("Got AS IP from tokens file: ");
  PRINTIP6ADDR(as_pairing_entry.claims);
  printf("\n");

  while(1) {
      printf("Executing check iteration.");

      authz_entry_iterator iterator = authz_entry_iterator_initialize();

      // Add all revoked tokens to a list (removing them all together later is more efficient).
      printf("Looping over all tokens to find revoked ones.\n");
      authz_entry* curr_entry = authz_entry_iterator_get_next(&iterator);
      int num_tokens_to_remove = 0;
      authz_entry* tokens_to_remove[MAX_AUTHZ_ENTRIES] = {0};
      while(curr_entry != 0) {
        printf("Curr entry kid: ");
        HEX_PRINTF(curr_entry->kid, KEY_ID_LENGTH);

        int token_was_revoked = 0;
        // 2. CoAP client to send request.
        // 4. Parse revocation response.

        // Add token to removal list if revoked, or free its temp memory if not.
        if(token_was_revoked) {
          printf("Adding token to removal list.\n");
          tokens_to_remove[num_tokens_to_remove++] = curr_entry;
        }
        else {
          free_authz_entry(curr_entry);
          free(curr_entry);
        }

        curr_entry = authz_entry_iterator_get_next(&iterator);
      }

      authz_entry_iterator_finish(iterator);

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
      }
      else {
        printf("No tokens to remove.");
      }

      printf("Finished executing check iteration.");

      // Set or reset timer and check again in a while.
      if(et == 0) {
        etimer_set(&et, CHECK_WAIT_TIME_SECS * CLOCK_SECOND);
      }
      else {
        etimer_reset(&et);
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  }
}

