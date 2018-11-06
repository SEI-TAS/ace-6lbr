#ifndef _ER_COAP_DTLS_H_
#define _ER_COAP_DTLS_H_

#include "er-coap.h"

struct dtls_context_t *
coap_init_communication_layer_dtls(uint16_t port);

void
coap_send_message_dtls(struct dtls_context_t * ctx, uip_ipaddr_t *addr, uint16_t port, uint8_t *data, uint16_t length);

void
coap_handle_receive_dtls(struct dtls_context_t *ctx);

#endif
