/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *
 *******************************************************************************/

#include "global.h"
#include "peer.h"
#include "dtls_debug.h"

extern void dtls_peer_timeout(void *);

#ifndef WITH_CONTIKI
void peer_init()
{
}

static inline dtls_peer_t *
dtls_malloc_peer() {
  return (dtls_peer_t *)malloc(sizeof(dtls_peer_t));
}

void
dtls_free_peer(dtls_peer_t *peer) {
  dtls_handshake_free(peer->handshake_params);
  dtls_security_free(peer->security_params[0]);
  dtls_security_free(peer->security_params[1]);
  free(peer);
}
#else /* WITH_CONTIKI */

#include "memb.h"
MEMB(peer_storage, dtls_peer_t, DTLS_PEER_MAX);

void
peer_init() {
  memb_init(&peer_storage);
}

static inline dtls_peer_t *
dtls_malloc_peer() {
  return memb_alloc(&peer_storage);
}

void
dtls_free_peer(dtls_peer_t *peer) {
#if defined WITH_CONTIKI && DTLS_CONN_TIMEOUT
  ctimer_stop(&peer->timeout);
#endif
  dtls_handshake_free(peer->handshake_params);
  dtls_security_free(peer->security_params[0]);
  dtls_security_free(peer->security_params[1]);
  memb_free(&peer_storage, peer);
}
#endif /* WITH_CONTIKI */

dtls_peer_t *
dtls_new_peer(struct dtls_context_t *ctx, const session_t *session) {
  dtls_peer_t *peer;

  peer = dtls_malloc_peer();
  if (peer) {
    memset(peer, 0, sizeof(dtls_peer_t));
    peer->ctx = ctx;
    memcpy(&peer->session, session, sizeof(session_t));
    peer->security_params[0] = dtls_security_new();

    if (!peer->security_params[0]) {
      dtls_free_peer(peer);
      return NULL;
    }

#if defined WITH_CONTIKI && DTLS_CONN_TIMEOUT
    ctimer_set(&peer->timeout, DTLS_CONN_TIMEOUT*CLOCK_SECOND, dtls_peer_timeout, peer);
#endif
    dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "dtls_new_peer", session);
  }

  return peer;
}

void dtls_peer_refresh_timeout(dtls_peer_t *peer) {
#if defined WITH_CONTIKI && DTLS_CONN_TIMEOUT
  ctimer_restart(&peer->timeout);
#endif
}
