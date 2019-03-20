/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#ifndef _ER_COAP_DTLS_H_
#define _ER_COAP_DTLS_H_

#include "er-coap.h"
#include "rest-engine.h"

struct dtls_context_t *
coap_init_communication_layer_dtls(uint16_t port);

void
coap_send_message_dtls(struct dtls_context_t * ctx, uip_ipaddr_t *addr, uint16_t port, uint8_t *data, uint16_t length);

void
coap_handle_receive_dtls(struct dtls_context_t *ctx);

int start_dtls_connection(struct dtls_context_t* ctx, uip_ipaddr_t* ip_addr, int no_port);

int close_current_dtls_connection();

void send_new_dtls_message(struct dtls_context_t* ctx, uip_ipaddr_t* ip_addr, int no_port, char* url,
                                  const unsigned char* payload, int payload_len,
                                  restful_response_handler callback, void* callback_data);

#endif
