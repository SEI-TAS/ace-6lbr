
#ifndef CWT_H
#define CWT_H

#include <time.h>

#define ISS 1
#define SUB 2
#define AUD 3
#define EXP 4
#define NBF 5
#define IAT 6
#define CTI 7
#define SCO 12
#define CNF 25

typedef struct cwt {
  char* iss;
  char* sub;
  char* aud;    // Only string auds supported; no support for array of auds.
  time_t exp;
  time_t nbf;
  time_t iat;
  char* cti;
  char* sco;
  char* cnf;
  unsigned char* kid;
  int kid_len;
  unsigned char* key;
  unsigned char* cbor_claims;
  int cbor_claims_len;
} cwt ;

typedef struct cosewt {
  char* nonce;
  char* pay;
} cosewt;

typedef struct token_entry {
  unsigned char* kid;
  unsigned char* key;
  unsigned char* cbor;
  int cbor_len;
} token_entry;

cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length);
cwt* parse_cbor_claims(const unsigned char* cbor_bytes, int cbor_bytes_len);
int validate_claims(const cwt* token, char** error);

#define KEY_ID_LENGTH 16
#define KEY_LENGTH 16
#define CBOR_SIZE_LENGTH 4

#endif // CWT_H
