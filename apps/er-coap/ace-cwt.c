#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "cn-cbor/cn-cbor.h"
#include "cwt.h"
#include "cfs/cfs.h"
#include "dtls.h"


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
static void create_token(signed long *claim, cwt *token, const cn_cbor* cb, char* out, char** end, int indent) {
  if (!cb) {
    *end = out;
    return;
  }
  int i;
  cn_cbor* cp;

  printf("Type: %d\n",cb->type);
  switch (cb->type) {
    case CN_CBOR_ARRAY:
    case CN_CBOR_MAP:
      for (cp = cb->first_child; cp; cp = cp->next) {
        create_token(claim, token, cp, out, &out, indent+2);
      }
      break;

    case CN_CBOR_BYTES:
      if(token->in_cnf > 0){
        printf("\ncnf CLM: %d\n", *claim);
      }
      printf("HEX:");
      for (i=0; i<cb->length; i++)
        printf("%02x", cb->v.str[i]);
      printf("\n");
      switch(*claim){
        case 25:
          token->cnf = (char *) malloc(cb->length+1);
          strncpy(token->cnf, cb->v.str, cb->length);
          token->cnf[cb->length] = '\0';
          printf("cnf is %s\n", token->cnf);
          token->in_cnf = 1;
          parse_cwt_token(cb->v.str, cb->length);
          token->in_cnf = 0;
          break;
        case 7:
          token->cti = (char *) malloc(cb->length+1);
          strncpy(token->cti, cb->v.str, cb->length);
          token->cti[cb->length] = '\0';
          printf("cti is %s\n", token->cti);
          break;
        case 2:
          token->kid = (char *) malloc(17);
          printf("kid len is %d\n", cb->length);
          strncpy(token->key, cb->v.str, cb->length);
          token->kid[cb->length] = '\0';
          printf("kid is %s\n", token->kid);
          break;
        case -1:
          token->key = (char *) malloc(cb->length+1);
          strncpy(token->key, cb->v.str, cb->length);
          token->key[cb->length+1] = '\0';
          printf("key is %s\n", token->key);
          break;
      }
      break;

    case CN_CBOR_TEXT:
      printf("LEN: %d\n",cb->length);
      printf("\nTXT: %s\n", cb->v.str);
      printf("CLM: %d\n", *claim);

      switch(*claim){
        case 1:
          token->iss = (char *) malloc(cb->length+1);
          strncpy(token->iss, cb->v.str, cb->length);
          token->iss[cb->length+1] = '\0';
          printf("iss is %s\n", token->iss);
          break;
        case 2:
          token->sub = (char *) malloc(cb->length+1);
          strncpy(token->sub, cb->v.str, cb->length);
          token->sub[cb->length+1] = '\0';
          printf("sub is %s\n", token->sub);
          break;
        case 3:
          token->aud = (char *) malloc(cb->length+1);
          strncpy(token->aud, cb->v.str, cb->length);
          token->aud[cb->length+1] = '\0';
          printf("aud is %s\n", token->aud);
          break;
        case 12:
          printf("It's 12\n");
          token->sco = (char *) malloc(cb->length+1);
          strncpy(token->sco, cb->v.str, cb->length);
          token->sco[cb->length+1] = '\0';
          printf("sco is %s\n", token->sco);
          break;
      }
      break;

    case CN_CBOR_UINT:
      printf("UINT: %lu\n", cb->v.uint);
      if(cb->v.uint < 256){
        *claim = cb->v.uint;
        printf("CLM: %d\n",*claim);
      }
      else {
        switch(*claim){
        case 4: token->exp = cb->v.uint; break;
        case 5: token->nbf = cb->v.uint; break;
        case 6: token->iat = cb->v.uint; break;
        }
        *claim = 0;
      }
      break;

    case CN_CBOR_INT:
      printf("NEGATIVE INT: %ld\n", cb->v.sint);
      if(cb->v.sint < 256){
        *claim = cb->v.sint;
        printf("CLM: %d\n",*claim);
      }
      else {
        *claim = 0;
      }
      break;

    default: break;
  }
}

// Reads a CWT token in CBOR byte format, and loads it into a cwt C struct.
cwt* parse_cwt_token(const unsigned char* cbor_token, int token_length) {
  char* nonce;
  //char key[KEY_LENGTH] = {0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  char key[KEY_LENGTH] = {0x7d, 0xd4, 0x43, 0x81, 0x1e, 0x32, 0x21, 0x08, 0x13, 0xc3, 0xc5, 0x11, 0x1e, 0x4d, 0x3d, 0xb4};
  cwt* token = (cwt*) malloc(sizeof(cwt));
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

  printf("Received COSE message, last byte is %x\n", cbor_token[token_length - 1]);

  // Byte 9 is 4x, indicating a byte string of x bytes.
  // Byte 10 indicates we have a CBOR array (81), byte 11 that the first value is text of size x (6x).
  // The actual size is the last 5 bits.
  // Bytes x after that indicate the actual key ID.
  int key_id_size_pos = 10;
  int key_id_size = cbor_token[key_id_size_pos] & 0x1F;
  printf("Key id size is %d.\n", key_id_size);

  int key_id_pos = key_id_size_pos + 1;
  char* key_id = (char*) malloc(key_id_size + 1);
  memcpy(key_id, &cbor_token[key_id_pos], key_id_size);
  key_id[key_id_size] = 0;
  printf("Key id is %s.\n", key_id);

  // After the key id, there are 2 bytes indicating that the nonce is coming, and it size. We assume it will always be 13.
  int nonce_pos = key_id_pos + key_id_size + 2;
  printf("Getting nonce.\n");
  nonce = (char *) malloc(NONCE_SIZE);
  memcpy(nonce, &cbor_token[nonce_pos], NONCE_SIZE);

  // After the nonce there are 2 bytes indicating that a byte string is coming and its size.
  printf("Getting encrypted claims.\n");
  int encrypted_cbor_claims_pos = nonce_pos + NONCE_SIZE + 2;
  int encrypted_cbor_claims_length = token_length - encrypted_cbor_claims_pos;
  char* encrypted_cbor_claims = (char *) malloc(encrypted_cbor_claims_length);
  memcpy(encrypted_cbor_claims, &cbor_token[encrypted_cbor_claims_pos], encrypted_cbor_claims_length);

  printf("Decrypting claims.\n");
  unsigned char* decrypted_cbor_claims = (unsigned char*) malloc(MAX_CBOR_CLAIMS_LEN);
  int decrypted_cbor_claims_len = dtls_decrypt(encrypted_cbor_claims, encrypted_cbor_claims_length,
                                               decrypted_cbor_claims, nonce, key, KEY_LENGTH, A_DATA, A_DATA_LEN);
  printf("%d bytes COSE decrypted\n", decrypted_cbor_claims_len);
  //free(encrypted_cbor_claims);

  printf("Decrypted CBOR:");
  int i;
  for (i=0; i < decrypted_cbor_claims_len; i++){
    printf(" %x", decrypted_cbor_claims[i]);
  }
  printf("\n");

  printf("Decoding claims CBOR.\n");
  char buf[1000];
  char *bufend = NULL;
  cn_cbor* claims = cn_cbor_decode(decrypted_cbor_claims, decrypted_cbor_claims_len CBOR_CONTEXT_PARAM, 0);
  if (claims) {
    signed long claim = 0;
    printf("Creating cwt struct from CBOR object.\n");
    create_token(&claim, token, claims, buf, &bufend, 0);
    token->cbor_claims = decrypted_cbor_claims;
    token->cbor_claims_length = decrypted_cbor_claims_len;
    return token;
  } else {
    printf("CBOR decode failed\n");
    return 0;
  }
}

// Stores the given token into the tokens file.
int store_token(cwt* token) {
  int bytes_written;
  int fd_tokens_file = cfs_open(TOKENS_FILE_NAME, CFS_WRITE | CFS_APPEND);
  if(fd_tokens_file != -1){
    char padding_format_string[6];

    // First write key id and key.
    snprintf(padding_format_string, 6, "%%0%ds", KEY_ID_LENGTH);
    printf("Formatting string: %s\n", padding_format_string);
    printf("Storing key id and key.\n");
    char padded_id[KEY_ID_LENGTH + 1] = { 0 };
    snprintf(padded_id, KEY_ID_LENGTH, padding_format_string, token->kid);
    bytes_written = cfs_write(fd_tokens_file, padded_id, strlen(padded_id));
    //free(padded_id);
    bytes_written = cfs_write(fd_tokens_file, token->key, KEY_LENGTH);

    // Now write CBOR claims length, and the CBOR claims.
    snprintf(padding_format_string, 6, "%%0%dd", CBOR_SIZE_LENGTH);
    printf("Formatting string: %s\n", padding_format_string);
    printf("Storing CBOR claims length and claims.\n");
    char length_as_string[CBOR_SIZE_LENGTH + 1] = { 0 };
    snprintf(length_as_string, CBOR_SIZE_LENGTH, padding_format_string, token->cbor_claims_length);
    char* padded_length_as_string = pad_with_zeros(length_as_string, CBOR_SIZE_LENGTH);
    bytes_written = cfs_write(fd_tokens_file, padded_length_as_string, strlen(padded_length_as_string));
    //free(padded_length_as_string);
    bytes_written = cfs_write(fd_tokens_file, token->cbor_claims, token->cbor_claims_length);

    cfs_close(fd_tokens_file);
    return 1;
  }
  else {
    return 0;
  }
}

// Add padding so that the given string always uses the max given bytes. "0" are added as padding.
char* pad_with_zeros(char* initial_string, int final_length) {
  printf("Unpadded id length is %d\n", strlen(initial_string));
  char* padded_string = (char *) malloc(final_length + 1);
  int padding_len = final_length - strlen(initial_string);
  int j;
  for (j = 0; j < padding_len; j++){
    padded_string[j] = "0";
  }
  padded_string[padding_len] = 0;
  strcat(padded_string, initial_string);
  return padded_string;
}
