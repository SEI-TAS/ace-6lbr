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
#include "er-coap-dtls.h"

#include "dtls.h"

#include "utils.h"
#include "cwt.h"
#include "dtls_helpers.h"
#include "resources.h"

#include <string.h>

#define DEBUG DEBUG_NONE
#include "dtls_debug.h"

/*---------------------------------------------------------------------------*/

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len);

static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len);

/*-----------------------------------------------------------------------------------*/
#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
         dtls_credentials_type_t type,
         const unsigned char *id, size_t id_len,
         unsigned char *result, size_t result_length) {

  printf("Checking key type request\n");
  if (type ==  DTLS_PSK_IDENTITY) {
    printf("PSK Key ID was requested\n");
    if (id_len) {
      // Not sure what is the purpose of the identity hint... return a different key id depending on the hint?
      dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
    }

    if (result_length < strlen(RS_ID)) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    // We return our identity.
    memcpy(result, RS_ID, strlen(RS_ID));
    return strlen(RS_ID);
  } else if (type == DTLS_PSK_KEY) {
    printf("PSK Key was requested, given key id\n");
    if (id) {
      printf("Id length is %u\n", (unsigned int) id_len);
      printf("Looking up id: ");
      HEX_PRINTF(id, id_len);
      int key_length = lookup_dtls_key(id, id_len, result, result_length);
      if(key_length == 0) {
          dtls_warn("Could not find or set PSK.\n");
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      printf("PSK has been found: ");
      HEX_PRINTF(result, key_length);
      return key_length;
    }
    else {
      dtls_warn("Key was requested, but no id was provided.\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }
  } else {
    return 0;
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif
/*-----------------------------------------------------------------------------------*/
struct dtls_context_t *
coap_init_communication_layer_dtls(uint16_t port)
{
  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = NULL,
#ifdef DTLS_PSK
    .get_psk_info = get_psk_info,
#endif
#ifdef DTLS_ECC
    .get_ecdsa_key = NULL,
    .verify_ecdsa_key = NULL,
#endif
  };

  printf("Creating default connection.\n");
  struct uip_udp_conn *server_conn = udp_new(NULL, 0, NULL);

  if(port != 0) {
    printf("Binding to specific port %d.\n", port);
    udp_bind(server_conn, UIP_HTONS(port));
  }

  dtls_set_log_level(DTLS_LOG_DEBUG);

  printf("Creating context.\n");
  struct dtls_context_t * ctx;
  ctx = dtls_new_context(server_conn);
  printf("Setting context handler.\n");
  if(ctx) {
    dtls_set_handler(ctx, &cb);
  }

  if(port != 0) {
    /* new connection with remote host */
    printf("COAP-DTLS listening on port %u\n", uip_ntohs(server_conn->lport));
  }
  else {
    printf("COAP-DTLS client connection set up.\n");
  }

  return ctx;
}
/*-----------------------------------------------------------------------------------*/
// Callback called by TinyDTLS context handler when sending a message. Does the actual
// UDP sending, data here is already DTLS encrypted.
static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len)
{
  // Get the connection structure from the context (why?), an fill it with the destination
  // data from the session object.
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  // Actually send the UDP data to the destination.
  printf("TinyDTLS called us: sending UDP message for port %d.\nDest address: ", uip_ntohs(conn->rport));
  PRINTIP6ADDR(&conn->ripaddr);
  printf("\n");
  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}
/*-----------------------------------------------------------------------------------*/
// Function called directly when we want to send a message through COAPS.
void
coap_send_message_dtls(struct dtls_context_t * ctx, uip_ipaddr_t *addr, uint16_t port, uint8_t *data, uint16_t length)
{
  // Store the destination IP and port in a session object.
  session_t session;
  dtls_session_init(&session);
  uip_ipaddr_copy(&session.addr, addr);
  session.port = port;

  // Call the TinyDTLS function to send message through DTLS.
  printf("Passing message for port %d to TinyDTLS.\n Dest address: ", uip_ntohs(port));
  PRINTIP6ADDR(addr);
  printf("\n");
  dtls_write(ctx, &session, data, length);
}
/*-----------------------------------------------------------------------------------*/
// Callback called by TinyDTLS once it has finished decrypting data. Data is now plain.
static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len)
{
  // Overwrite the global data buffers with the now unencrypted data and length, so DTLS will
  // be transparent to the handler function.
  uip_len = len;
  memmove(uip_appdata, data, len);

  // Call a function to parse COAP and handle the actual message.
  coap_receive(ctx, 1);
  return 0;
}
/*-----------------------------------------------------------------------------------*/
// Function called when a new TCP/IP event is received, with new COAPS data.
void
coap_handle_receive_dtls(struct dtls_context_t *ctx)
{
  session_t session;

  // We use the "uip_newdata()" to check if there is actually data, and ignore orther TCP/IP events.
  if(uip_newdata()) {
    printf("We recieved new data!\n");
    // Get connection info into a session object.
    dtls_session_init(&session);
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;

    // New data is waiting for us at the uip_appdata buffer. Give it to TinyDTLS to process.
    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}
