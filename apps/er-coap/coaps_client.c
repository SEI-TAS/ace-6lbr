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
#include "contiki-net.h"
#include "er-coap.h"
#include "er-coap-engine.h"

#include "dtls_debug.h"

#include <stdlib.h>
#include <string.h>

#define DEBUG DEBUG_NONE

#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

static uint16_t current_mid = 0;

/*-----------------------------------------------------------------------------------*/
// Set up for our DTLS outgoing connections.
struct dtls_context_t* coaps_client_setup() {
  printf("Setting up DTLS for revoked tokens checker.\n");

  current_mid = random_rand();

  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = NULL,
    .get_psk_info = get_psk_info,  // TODO: we may need a different function, or different way for it to work.
  };

  // TODO: what do we need to send/store as app_data in our context? Not a server connection... what? Nothing?
  struct dtls_context_t * ctx;
  ctx = dtls_new_context(app_data);
  if(ctx) {
    dtls_set_handler(ctx, &cb);
  }

  printf("COAP-DTLS set up for outgoing connections.\n");
  return ctx;
}

/*-----------------------------------------------------------------------------------*/
// Function called directly when we want to send a message through COAPS.
void
coaps_send_message(struct dtls_context_t* ctx, uip_ipaddr_t* addr, uint16_t port, uint8_t* data, uint16_t length)
{
  // Store the destination IP and port in a session object.
  session_t session;
  dtls_session_init(&session);
  uip_ipaddr_copy(&session.addr, addr);
  session.port = port;

  // Call the TinyDTLS function to send message through DTLS.
  dtls_write(ctx, &session, data, length);
}

/*-----------------------------------------------------------------------------------*/
// Callback called by TinyDTLS context handler when sending a message. Does the actual
// UDP sending, data by this time is encrypted.
static int send_to_peer(struct dtls_context_t *ctx, session_t* session, uint8 *data, size_t len)
{
  struct uip_udp_conn* client_conn = udp_new(&session->addr, UIP_HTONS(session->port), NULL);
  uip_udp_packet_send(conn, data, len);
  return len;
}

/*-----------------------------------------------------------------------------------*/
// Function called when a new TCP/IP event is received, with new COAPS data.
void
coaps_handle_receive(struct dtls_context_t* ctx)
{
  // We use the "uip_newdata()" to check if there is actually data for us.
  if(uip_newdata()) {
    // Get connection info.
    session_t session;
    dtls_session_init(&session);
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;

    // New data is waiting for us at the uip_appdata buffer. Give it to TinyDTLS to process.
    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}

/*-----------------------------------------------------------------------------------*/
// Callback called by TinyDTLS once it has finished decrypting it. Data is now plain.
static int read_from_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len)
{
  // Let's overwrite the global data buffers with the now unencrypted data and length.
  uip_len = len;
  memmove(uip_appdata, data, len);

  // Call the method to parse and do something with the message.
  // TODO: we probably need to create a new handler method to be used here.
  coap_receive(ctx, 1);
  return 0;
}
