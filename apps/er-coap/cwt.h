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
  char* kid;
  char* ktype;
  char* key;
  int in_cnf;
  char* cbor_claims;
  int cbor_claims_length;
} cwt ;

typedef struct cosewt {
  char* nonce;
  char* pay;
} cosewt;

typedef struct token_entry {
  char* kid;
  char* key;
  char* cbor;
} token_entry;

cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length);
int store_token(cwt* token);

#define MAX_KEY_ID_LEN 16
#define KEY_ID_LENGTH 16
#define KEY_LENGTH 16
#define CBOR_SIZE_LENGTH 4
#define TOKENS_FILE_NAME "tokens"
