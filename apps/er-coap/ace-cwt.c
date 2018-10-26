#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cfs/cfs.h"
#include "dtls.h"

#include "cn-cbor/cn-cbor/cn-cbor.h"
#include "cwt.h"
#include "key-token-store.h"
#include "utils.h"
#include "resources.h"

#ifdef USE_CBOR_CONTEXT
#define CBOR_CONTEXT_PARAM , NULL
#else
#define CBOR_CONTEXT_PARAM
#endif

#define A_DATA_LEN 0
#define NONCE_SIZE 13
#define MAX_CBOR_CLAIMS_LEN 200
#define COSE_PROTECTED_HEADER_SIZE 6

// Parses the unencrypted CBOR bytes of a CWT token, and loads all claims into a cwt C struct object.
static void parse_claims(signed long *curr_claim, cwt *token, const cn_cbor* cbor_object) {
  if (!cbor_object) {
    return;
  }

  printf("Analyzing object of type: %d\n", cbor_object->type);
  switch (cbor_object->type) {
    case CN_CBOR_ARRAY:
      printf("Type is Array\n");
    case CN_CBOR_MAP:
      printf("Type is Map\n");
      printf("Will analyze children objects\n");
      cn_cbor* current;
      for (current = cbor_object->first_child; current; current = current->next) {
        parse_claims(curr_claim, token, current);
      }
      printf("Finished analyzing children objects\n");
      break;

    case CN_CBOR_BYTES:
      printf("Type is Byte String\n");
      HEX_PRINTF(cbor_object->v.str, cbor_object->length)
      switch(*curr_claim){
        case 7:     // CTI
          token->cti = (char *) malloc(cbor_object->length);
          memcpy(token->cti, cbor_object->v.str, cbor_object->length);
          printf("cti found\n");
          break;
        case 2:     // KID (inside CNF)
          token->kid = (unsigned char *) malloc(cbor_object->length);
          token->kid_len = cbor_object->length;
          printf("kid len is %d\n", token->kid_len);
          memcpy(token->kid, cbor_object->v.str, token->kid_len);
          printf("kid found\n");
          break;
        case -1:    // KEY (inside CNF)
          token->key = (unsigned char *) malloc(cbor_object->length);
          memcpy(token->key, cbor_object->v.str, cbor_object->length);
          printf("key found\n");
          break;
      }
      *curr_claim = 0;
      break;

    case CN_CBOR_TEXT:
      printf("Type is Text\n");
      printf("Current CLM: %ld\n", *curr_claim);
      printf("LEN: %d\n",cbor_object->length);
      printf("TXT: %.*s\n", cbor_object->length, cbor_object->v.str);

      switch(*curr_claim){
        case 1: // ISS
          token->iss = (char *) malloc(cbor_object->length + 1);
          strncpy(token->iss, cbor_object->v.str, cbor_object->length);
          token->iss[cbor_object->length] = '\0';
          printf("iss is %s\n", token->iss);
          break;
        case 2: // SUB
          token->sub = (char *) malloc(cbor_object->length + 1);
          strncpy(token->sub, cbor_object->v.str, cbor_object->length);
          token->sub[cbor_object->length] = '\0';
          printf("sub is %s\n", token->sub);
          break;
        case 3: // AUD
          token->aud = (char *) malloc(cbor_object->length + 1);
          strncpy(token->aud, cbor_object->v.str, cbor_object->length);
          token->aud[cbor_object->length] = '\0';
          printf("aud is %s\n", token->aud);
          break;
        case 12:    // SCOPE
          token->sco = (char *) malloc(cbor_object->length + 1);
          strncpy(token->sco, cbor_object->v.str, cbor_object->length);
          token->sco[cbor_object->length] = '\0';
          printf("sco is %s\n", token->sco);
          break;
      }
      *curr_claim = 0;
      break;

    case CN_CBOR_UINT:
      printf("Type is Positive Int\n");
      printf("UINT: %lu\n", cbor_object->v.uint);
      if(cbor_object->v.uint < 256){
        *curr_claim = cbor_object->v.uint;
        printf("Found CLM: %ld\n", *curr_claim);
      }
      else {
        switch(*curr_claim){
          case 4:
            token->exp = cbor_object->v.uint;
            printf("exp is %lu\n", token->exp);
            break;
          case 5:
            token->nbf = cbor_object->v.uint;
            printf("nbf is %lu\n", token->nbf);
            break;
          case 6:
            token->iat = cbor_object->v.uint;
            printf("iat is %lu\n", token->iat);
            break;
        }
        *curr_claim = 0;
      }
      break;

    case CN_CBOR_INT:
      printf("Type is Negative Int\n");
      printf("NEGATIVE INT: %ld\n", cbor_object->v.sint);
      if(cbor_object->v.sint < 256){
        *curr_claim = cbor_object->v.sint;
        printf("Found CLM: %ld\n", *curr_claim);
      }
      else {
        *curr_claim = 0;
      }
      break;

    default: break;
  }
}

// Reads a CWT token in CBOR byte format, and loads it into a cwt C struct.
cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length) {
  //char key[KEY_LENGTH] = {0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  //char key[KEY_LENGTH] = {0x7d, 0xd4, 0x43, 0x81, 0x1e, 0x32, 0x21, 0x08, 0x13, 0xc3, 0xc5, 0x11, 0x1e, 0x4d, 0x3d, 0xb4};

  unsigned char A_DATA[A_DATA_LEN];

  // The structure of this wrapper is: 16 [<protected-headers-as-b-string>, <unprotected-headers-as-map>, <cyphertext-as-b-string>]
  // We assume byte 1 in CWT is 0xD0, 16, which means COSE_Encrypt0, the type of COSE wrapper we are using.
  // We assume byte 2 is 83, which indicates we have an array.
  // We assume byte 3, 43, indicates a byte string of 3 bytes.
  // Bytes 4,5,6 should be A1010A, meaning profile AES_CCM_16_64_128 for the encrypted cypher.
  // Byte 7 should be A2, indicating a map for the unprotected header params.
  // Byte 8 should be 04, indicating the key id to be used.

  //char protected_header[COSE_PROTECTED_HEADER_SIZE];
  //memcpy(header, cbor_token, COSE_PROTECTED_HEADER_SIZE);
  ///if (header == "\xD0\x83\x43\xA1\x01\x0A\xA2\04\"){

  printf("Received COSE message, last byte is %02x\n", cbor_token[token_length - 1]);

  // Byte 9 is 4x, indicating a byte string of x bytes.
  // Byte 10 indicates we have a CBOR array (81), byte 11 that the first value is text of size x (6x).
  // The actual size is the last 5 bits.
  // Bytes x after that indicate the actual key ID.
  int key_id_size_pos = 10;
  int key_id_size = cbor_token[key_id_size_pos] & 0x1F; // We need 5 lower bits to get size.
  printf("Key id size is %d.\n", key_id_size);

  int key_id_pos = key_id_size_pos + 1;
  char* key_id = (char*) malloc(key_id_size + 1);
  memcpy(key_id, &cbor_token[key_id_pos], key_id_size);
  key_id[key_id_size] = 0;
  printf("Key id is %s.\n", key_id);

  printf("Looking for stored key associated with kid.\n");
  token_entry pairing_key_info;
  unsigned char* padded_key_id = left_pad_array((unsigned char*) key_id, key_id_size, KEY_ID_LENGTH, 0);
  if(find_token_entry(padded_key_id, KEY_ID_LENGTH, &pairing_key_info) == 0) {
    printf("Could not find key to decrypt COSE wrapper of CWT; aborting parsing token.\n");
    return 0;
  }

  // After the key id, there are 2 bytes indicating that the nonce is coming, and it size. We assume it will always be 13.
  int nonce_pos = key_id_pos + key_id_size + 2;
  printf("Getting nonce.\n");
  unsigned char* nonce = (unsigned char *) malloc(NONCE_SIZE);
  memcpy(nonce, &cbor_token[nonce_pos], NONCE_SIZE);

  // After the nonce there are 2 bytes indicating that a byte string is coming and its size.
  printf("Getting encrypted claims.\n");
  int encrypted_cbor_pos = nonce_pos + NONCE_SIZE + 2;
  int encrypted_cbor_length = token_length - encrypted_cbor_pos;
  unsigned char* encrypted_cbor = (unsigned char *) malloc(encrypted_cbor_length);
  memcpy(encrypted_cbor, &cbor_token[encrypted_cbor_pos], encrypted_cbor_length);

  printf("Decrypting claims.\n");
  unsigned char* decrypted_cbor = (unsigned char*) malloc(MAX_CBOR_CLAIMS_LEN);
  int decrypted_cbor_len = dtls_decrypt(encrypted_cbor, encrypted_cbor_length,
                                        decrypted_cbor, nonce, pairing_key_info.key, KEY_LENGTH, A_DATA, A_DATA_LEN);
  printf("%d bytes COSE decrypted\n", decrypted_cbor_len);
  //free(encrypted_cbor);
  //free(nonce);

  printf("Decrypted CBOR:");
  HEX_PRINTF(decrypted_cbor, decrypted_cbor_len)
  printf("Decrypted CBOR length: %d\n", decrypted_cbor_len);

  // Parse bytes into a cwt object.
  cwt* token_info = parse_cbor_claims(decrypted_cbor, decrypted_cbor_len);

  // Add original CBOR bytes so we can serialize it faster if needed.
  token_info->cbor_claims = decrypted_cbor;
  token_info->cbor_claims_len = decrypted_cbor_len;
  return token_info;
}

// Gets CBOR bytes with claims and loads into into cwt struct.
cwt* parse_cbor_claims(const unsigned char* cbor_bytes, int cbor_bytes_len) {
  printf("Decoding claims from CBOR bytes into CBOR object.\n");
  cn_cbor* cbor_claims = cn_cbor_decode(cbor_bytes, cbor_bytes_len CBOR_CONTEXT_PARAM, 0);
  if (!cbor_claims) {
    printf("CBOR decode failed\n");
    return 0;
  }

  printf("Parsing claims into cwt object.\n");
  cwt* token_info = (cwt*) malloc(sizeof(cwt));
  token_info->sco = 0;
  token_info->aud = 0;
  token_info->exp = 0;
  long curr_claim = 0;
  parse_claims(&curr_claim, token_info, cbor_claims);
  token_info->cbor_claims_len = 0;
  printf("Finished parsing claims into cwt object.\n");

  return token_info;
}

#define INVALID_AUDIENCE_ERROR "Invalid audience: %s"
#define TOKEN_EXPIRED_ERROR "Token has expired"
#define NO_SCOPE_ERROR "Token has no scope"
#define UNKNOWN_SCOPE_ERROR "Unknown scope: %s"

int validate_claims(const cwt* token, char** error) {
  printf("Validating tokens.\n");
  // 1. Check if the token has expired.
  if(time(NULL) > token->exp) {
    int error_len = strlen(TOKEN_EXPIRED_ERROR) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, TOKEN_EXPIRED_ERROR);
    printf("Error validating token: %s\n", *error);
    return 0;
  }

  // 2. Check if we are the audience.
  if(strncmp(RS_ID, token->aud, strlen(RS_ID)) != 0) {
    int error_len = strlen(INVALID_AUDIENCE_ERROR) - 2 + strlen(token->aud) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, INVALID_AUDIENCE_ERROR, token->aud);
    printf("Error validating token: %s\n", *error);
    return 0;
  }

  // 3. Check if the token has a scope.
  if(strlen(token->sco) == 0) {
    int error_len = strlen(NO_SCOPE_ERROR) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, NO_SCOPE_ERROR);
    printf("Error validating token: %s\n", *error);
    return 0;
  }

  // 4. Check if the token has a known scope.
  if(strstr(SCOPES, token->sco) == 0) {
    int error_len = strlen(UNKNOWN_SCOPE_ERROR) - 2 + strlen(token->sco) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, UNKNOWN_SCOPE_ERROR, token->sco);
    printf("Error validating token: %s\n", *error);
    return 0;
  }

  printf("All claims are valid.\n");
  return 1;
}