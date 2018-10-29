
#ifndef DTLS_HELPERS_H
#define DTLS_HELPERS_H

#include <stdlib.h>
#include "er-coap-dtls.h"

int lookup_dtls_key(const unsigned char * const id, size_t id_len,
         unsigned char * const result, size_t result_length);
int find_dtls_context_key_id(context_t* ctx, unsigned char** identity);

#endif // DTLS_HELPERS_H