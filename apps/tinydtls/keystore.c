#include "contiki.h"
#include "keystore.h"
#include "key-token-store.h"


void keystore_init(){
  initialize_key_token_store();
}

