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
  char* k;
  int in_cnf;
} cwt ;

typedef struct cosewt {
  char* nonce;
  char* pay;
} cosewt;

typedef struct token_entry {
  char* kid;
  char* key
  char* cbor;
} token_entry;

unsigned char* read_cbor(const unsigned char* payload, int i_len);
