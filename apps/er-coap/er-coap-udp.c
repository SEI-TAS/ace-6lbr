/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#include "contiki.h"
#include "contiki-net.h"
#include "er-coap.h"
#include "er-coap-engine.h"

#include <string.h>

#define DEBUG DEBUG_NONE
#include "uip-debug.h"

/*-----------------------------------------------------------------------------------*/
context_t *
coap_init_communication_layer(uint16_t port)
{
  /* new connection with remote host */
  context_t * ctx = udp_new(NULL, 0, NULL);
  udp_bind(ctx, port);
  PRINTF("Listening on port %u\n", uip_ntohs(ctx->lport));
  return ctx;
}
/*-----------------------------------------------------------------------------------*/
void
coap_send_message(context_t * ctx, uip_ipaddr_t *addr, uint16_t port, uint8_t *data, uint16_t length)
{
  /* Configure connection to reply to client */
  uip_ipaddr_copy(&ctx->ripaddr, addr);
  ctx->rport = port;

  uip_udp_packet_send(ctx, data, length);
  PRINTF("-sent UDP datagram (%u)-\n", length);

  /* Restore server connection to allow data from any node */
  memset(&ctx->ripaddr, 0, sizeof(ctx->ripaddr));
  ctx->rport = 0;
}
/*-----------------------------------------------------------------------------------*/
void
coap_handle_receive(context_t * ctx)
{
  coap_receive(ctx, 0);
}
