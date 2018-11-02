#ifndef KEY_TOKEN_STORE_H
#define KEY_TOKEN_STORE_H

#include <stdlib.h>
#include "cwt.h"

void initialize_key_token_store();
int store_token(cwt* token);
int find_token_entry(const unsigned char* const index, size_t idx_len, token_entry *result);
void free_token_entry(token_entry* entry);

#endif // KEY_TOKEN_STORE_H