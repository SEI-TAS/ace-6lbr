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
  char* aud;
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
} token_entry;

cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length);
cwt* parse_cbor_claims_into_cwt_struct(const unsigned char* cbor_bytes, int cbor_bytes_len);

#define KEY_ID_LENGTH 16
#define KEY_LENGTH 16
#define CBOR_SIZE_LENGTH 4
