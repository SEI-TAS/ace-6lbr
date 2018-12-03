/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cfs/cfs.h"

#include "tinydtls_aes.h"
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

#define NONCE_SIZE 13
#define MAC_LENGTH 8
#define COSE_PROTECTED_HEADER_SIZE 6


#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#define HEX_PRINTF(byte_array, length)
#endif

// Parses the unencrypted CBOR bytes of a CWT token, and loads all claims into a cwt C struct object.
static void parse_claims(signed long *curr_claim, cwt *token, const cn_cbor* cbor_object) {
  if (!cbor_object) {
    return;
  }

  PRINTF("Analyzing object of type: %d\n", cbor_object->type);
  switch (cbor_object->type) {
    case CN_CBOR_ARRAY:
      PRINTF("Type is Array\n");
    case CN_CBOR_MAP:
      PRINTF("Type is Map\n");
      PRINTF("Will analyze children objects\n");
      cn_cbor* current;
      for (current = cbor_object->first_child; current; current = current->next) {
        parse_claims(curr_claim, token, current);
      }
      PRINTF("Finished analyzing children objects\n");
      break;

    case CN_CBOR_BYTES:
      PRINTF("Type is Byte String\n");
      HEX_PRINTF(cbor_object->v.str, cbor_object->length)
      switch(*curr_claim){
        case CTI:
          token->cti = (char *) malloc(cbor_object->length);
          memcpy(token->cti, cbor_object->v.str, cbor_object->length);
          PRINTF("cti found\n");
          break;
        case CNF_KID:     // KID (inside CNF)
          token->kid = (unsigned char *) malloc(cbor_object->length);
          token->kid_len = cbor_object->length;
          PRINTF("kid len is %d\n", token->kid_len);
          memcpy(token->kid, cbor_object->v.str, token->kid_len);
          PRINTF("kid found\n");
          break;
        case CNK_KEY:    // KEY (inside CNF)
          token->key = (unsigned char *) malloc(cbor_object->length);
          memcpy(token->key, cbor_object->v.str, cbor_object->length);
          PRINTF("key found\n");
          break;
      }
      *curr_claim = 0;
      break;

    case CN_CBOR_TEXT:
      PRINTF("Type is Text\n");
      PRINTF("Current CLM: %ld\n", *curr_claim);
      PRINTF("LEN: %d\n",cbor_object->length);
      PRINTF("TXT: %.*s\n", cbor_object->length, cbor_object->v.str);

      switch(*curr_claim){
        case ISS:
          token->iss = (char *) malloc(cbor_object->length + 1);
          strncpy(token->iss, cbor_object->v.str, cbor_object->length);
          token->iss[cbor_object->length] = '\0';
          PRINTF("iss is %s\n", token->iss);
          break;
        case SUB:
          token->sub = (char *) malloc(cbor_object->length + 1);
          strncpy(token->sub, cbor_object->v.str, cbor_object->length);
          token->sub[cbor_object->length] = '\0';
          PRINTF("sub is %s\n", token->sub);
          break;
        case AUD:
          token->aud = (char *) malloc(cbor_object->length + 1);
          strncpy(token->aud, cbor_object->v.str, cbor_object->length);
          token->aud[cbor_object->length] = '\0';
          PRINTF("aud is %s\n", token->aud);
          break;
        case SCO:
          token->sco = (char *) malloc(cbor_object->length + 1);
          strncpy(token->sco, cbor_object->v.str, cbor_object->length);
          token->sco[cbor_object->length] = '\0';
          PRINTF("sco is %s\n", token->sco);
          break;
      }
      *curr_claim = 0;
      break;

    case CN_CBOR_UINT:
      PRINTF("Type is Positive Int\n");
      PRINTF("UINT: %lu\n", cbor_object->v.uint);
      if(cbor_object->v.uint < 256){
        *curr_claim = cbor_object->v.uint;
        PRINTF("Found CLM: %ld\n", *curr_claim);
      }
      else {
        switch(*curr_claim){
          case EXP:
            token->exp = cbor_object->v.uint;
            PRINTF("exp is %lu\n", token->exp);
            break;
          case NBF:
            token->nbf = cbor_object->v.uint;
            PRINTF("nbf is %lu\n", token->nbf);
            break;
          case IAT:
            token->iat = cbor_object->v.uint;
            PRINTF("iat is %lu\n", token->iat);
            break;
          case EXI:
            token->exi = cbor_object->v.uint;
            PRINTF("exi is %lu\n", token->exi);
            break;
        }
        *curr_claim = 0;
      }
      break;

    case CN_CBOR_INT:
      PRINTF("Type is Negative Int\n");
      PRINTF("NEGATIVE INT: %ld\n", cbor_object->v.sint);
      if(cbor_object->v.sint < 256){
        *curr_claim = cbor_object->v.sint;
        PRINTF("Found CLM: %ld\n", *curr_claim);
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

  PRINTF("Received COSE message, last byte is %02x\n", cbor_token[token_length - 1]);

  // Byte 9 is 4x, indicating a byte string of x bytes.
  // Byte 10 indicates we have a CBOR array (81), byte 11 that the first value is text of size x (6x).
  // The actual size is the last 5 bits.
  // Bytes x after that indicate the actual key ID.
  int key_id_size_pos = 10;
  int key_id_size = cbor_token[key_id_size_pos] & 0x1F; // We need 5 lower bits to get size.
  PRINTF("Key id size is %d.\n", key_id_size);

  int key_id_pos = key_id_size_pos + 1;
  char* key_id = (char*) malloc(key_id_size + 1);
  memcpy(key_id, &cbor_token[key_id_pos], key_id_size);
  key_id[key_id_size] = 0;
  PRINTF("Key id is %s.\n", key_id);

  PRINTF("Looking for stored key associated with kid.\n");
  token_entry pairing_key_info = {0};
  unsigned char* padded_key_id = left_pad_array((unsigned char*) key_id, key_id_size, KEY_ID_LENGTH, 0);
  if(find_token_entry(padded_key_id, KEY_ID_LENGTH, &pairing_key_info) == 0) {
    PRINTF("Could not find key to decrypt COSE wrapper of CWT; aborting parsing token.\n");
    return 0;
  }
  PRINTF("Key is: ");
  HEX_PRINTF(pairing_key_info.key, KEY_LENGTH);

  // After the key id, there are 2 bytes indicating that the nonce is coming, and it size. We assume it will always be 13.
  int nonce_pos = key_id_pos + key_id_size + 2;
  PRINTF("Getting nonce.\n");
  unsigned char* nonce = (unsigned char *) malloc(NONCE_SIZE);
  memcpy(nonce, &cbor_token[nonce_pos], NONCE_SIZE);
  PRINTF("Nonce is: ");
  HEX_PRINTF(nonce, NONCE_SIZE);

  // After the nonce there are 2 bytes indicating that a byte string is coming and its size.
  PRINTF("Getting encrypted claims.\n");
  int encrypted_cbor_pos = nonce_pos + NONCE_SIZE + 2;
  int encrypted_cbor_length = token_length - encrypted_cbor_pos;
  unsigned char* encrypted_cbor = (unsigned char *) malloc(encrypted_cbor_length);
  memcpy(encrypted_cbor, &cbor_token[encrypted_cbor_pos], encrypted_cbor_length);
  PRINTF("Encrypted CBOR claims length: %d\n", encrypted_cbor_length);

  PRINTF("Decrypting claims.\n");
  unsigned char* decrypted_cbor = (unsigned char*) malloc(encrypted_cbor_length);
  int decrypted_cbor_len = dtls_decrypt_with_nounce_len(encrypted_cbor, encrypted_cbor_length,
                                                        decrypted_cbor,
                                                        nonce, NONCE_SIZE,
                                                        pairing_key_info.key, KEY_LENGTH);
  PRINTF("%d bytes COSE decrypted\n", decrypted_cbor_len);

  PRINTF("Freeing temporary allocated memory for decryption.\n");
  free_token_entry(&pairing_key_info);
  free(key_id);
  free(padded_key_id);
  free(nonce);
  free(encrypted_cbor);

  PRINTF("Decrypted CBOR:");
  HEX_PRINTF(decrypted_cbor, decrypted_cbor_len)
  PRINTF("Decrypted CBOR length: %d\n", decrypted_cbor_len);

  // Parse bytes into a cwt object.
  cwt* token_info = parse_cbor_claims(decrypted_cbor, decrypted_cbor_len);

  // Add original CBOR bytes so we can serialize it faster if needed.
  token_info->cbor_claims = decrypted_cbor;
  token_info->cbor_claims_len = decrypted_cbor_len;

  // And time token was received (now)
  token_info->time_received_seconds = (uint64_t) time(NULL);
  token_info->time_received_size = sizeof(uint64_t);

  return token_info;
}

// Gets CBOR bytes with claims and loads into into cwt struct.
cwt* parse_cbor_claims(const unsigned char* cbor_bytes, int cbor_bytes_len) {
  PRINTF("Decoding claims from CBOR bytes into CBOR object.\n");
  cn_cbor* cbor_claims = cn_cbor_decode(cbor_bytes, cbor_bytes_len CBOR_CONTEXT_PARAM, 0);
  if (!cbor_claims) {
    PRINTF("CBOR decode failed\n");
    return 0;
  }

  PRINTF("Parsing claims into cwt object.\n");
  cwt* token_info = (cwt*) malloc(sizeof(cwt));
  token_info->sco = 0;
  token_info->aud = 0;
  token_info->exp = 0;
  token_info->exi = 0;
  long curr_claim = 0;
  parse_claims(&curr_claim, token_info, cbor_claims);
  token_info->cbor_claims_len = 0;
  PRINTF("Finished parsing claims into cwt object.\n");

  return token_info;
}

#define INVALID_AUDIENCE_ERROR "Invalid audience: %s"
#define TOKEN_EXPIRED_ERROR "Token has expired"
#define NO_SCOPE_ERROR "Token has no scope"
#define UNKNOWN_SCOPE_ERROR "Unknown scope: %s"

int validate_claims(const cwt* token, char** error) {
  PRINTF("Validating tokens.\n");

  // TODO: time() needs gettimeofday() implementation for CC2538dk TI boards for this version to compile and work.
  // 1. Check if the token has expired. We use the exi claim and not the exp claim since exp requires clock synch.
  uint64_t curr_time_seconds = (uint64_t) time(NULL);
  uint64_t time_since_received = curr_time_seconds - token->time_received_seconds;
  PRINTF("Checking if time since token was received %ld is greater than expires in time %ld\n", time_since_received, token->exi);
  if((token->exi != 0) && (time_since_received > token->exi)) {
    int error_len = strlen(TOKEN_EXPIRED_ERROR) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, TOKEN_EXPIRED_ERROR);
    PRINTF("Error validating token: %s\n", *error);
    return 0;
  }

  // 2. Check if we are the audience.
  if(strncmp(RS_ID, token->aud, strlen(RS_ID)) != 0) {
    int error_len = strlen(INVALID_AUDIENCE_ERROR) - 2 + strlen(token->aud) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, INVALID_AUDIENCE_ERROR, token->aud);
    PRINTF("Error validating token: %s\n", *error);
    return 0;
  }

  // 3. Check if the token has a scope.
  if(strlen(token->sco) == 0) {
    int error_len = strlen(NO_SCOPE_ERROR) + 1;
    *error = (char*) malloc(error_len);
    snprintf(*error, error_len, NO_SCOPE_ERROR);
    PRINTF("Error validating token: %s\n", *error);
    return 0;
  }

  // 4. Check if the token has a known scope.
  PRINTF("Checking if all scopes in token are known: %s\n", token->sco);
  int scope_list_len = strlen(token->sco) + 1;
  char* scope_list = (char*) malloc(scope_list_len);
  memcpy(scope_list, token->sco, scope_list_len);
  char* curr_scope = strtok(scope_list, " ");
  while(curr_scope) {
    // Check if this scope is in the list of known scopes.
    PRINTF("Checking next scope: %s, length %u\n", curr_scope, (unsigned int) strlen(curr_scope));
    if(strstr(SCOPES, curr_scope) == 0) {
      int error_len = strlen(UNKNOWN_SCOPE_ERROR) - 2 + strlen(curr_scope) + 1;
      *error = (char*) malloc(error_len);
      snprintf(*error, error_len, UNKNOWN_SCOPE_ERROR, curr_scope);
      PRINTF("Error validating token: %s\n", *error);
      free(scope_list);
      return 0;
    }

    // Move to next scope.
    curr_scope = strtok(NULL, " ");
  }
  free(scope_list);

  PRINTF("All claims are valid.\n");
  return 1;
}
