/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

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
#define EXI 35

#define CNF_KID 2
#define CNK_KEY -1

typedef struct cwt {
  char* iss;
  char* sub;
  char* aud;    // Only string auds supported; no support for array of auds.
  time_t exp;
  uint64_t exi;
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
  uint64_t time_received_seconds;
  int time_received_size;
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
  uint64_t time_received_seconds;
} token_entry;

cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length);
cwt* parse_cbor_claims(const unsigned char* cbor_bytes, int cbor_bytes_len);
int validate_claims(const cwt* token, char** error);

#define KEY_ID_LENGTH 16
#define KEY_LENGTH 16
#define CBOR_SIZE_LENGTH 4

#endif // CWT_H
