/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

/**
 * \file
 *         Main ace-rs process and initialisation
 */


#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip-debug.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "rest-engine.h"
#include "dtls.h"

/*---------------------------------------------------------------------------*/
PROCESS(acers, "ACE RS");
AUTOSTART_PROCESSES(&acers);
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  printf("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}

PROCESS_THREAD(acers, ev, data)
{
  PROCESS_BEGIN();

  printf("Starting ACE RS (" CONTIKI_VERSION_STRING ")\n");

  // Setup IPv6 address.
  uint8_t default_prefix[16] = {0};
  default_prefix[0] = 253; // 0xfd

  uip_ip6addr_t wsn_net_prefix;
  uint8_t wsn_net_prefix_len;
  uip_ipaddr_t wsn_ip_addr;

  memcpy(wsn_net_prefix.u8, &default_prefix,
         sizeof(default_prefix));
  wsn_net_prefix_len = sizeof(default_prefix);
  uip_ipaddr_copy(&wsn_ip_addr, &wsn_net_prefix);
  uip_ds6_set_addr_iid(&wsn_ip_addr, &uip_lladdr);
  uip_ds6_addr_add(&wsn_ip_addr, 0, ADDR_AUTOCONF);

  // Initialize DTLS and both Erbium servers (CoAP and CoAPs).
  dtls_init();
  rest_init_engine();

  printf("CoAP servers started.\n");
  printf("Checking IP addresses.\n");
  print_local_addresses();

  PROCESS_END();
}
