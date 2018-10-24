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
static void parse_claims(signed long *curr_claim, cwt *token, const cn_cbor* cbor_object) {
  if (!cbor_object) {
    return;
  }

  printf("Analyzing object of type: %d\n", cbor_object->type);
  switch (cbor_object->type) {
    case CN_CBOR_ARRAY:
      printf("Type is Array");
    case CN_CBOR_MAP:
      printf("Type is Map");
      cn_cbor* current;
      for (current = cbor_object->first_child; current; current = current->next) {
        parse_claims(curr_claim, token, current_object);
      }
      break;

    case CN_CBOR_BYTES:
      printf("Type is Byte String");
      if(token->in_cnf > 0){
        printf("\nInside cnf CLM: %d\n", *curr_claim);
      }
      int i;
      printf("HEX:");
      for (i=0; i<cbor_object->length; i++)
        printf("%02x", cbor_object->v.str[i]);
      printf("\n");
      switch(*curr_claim){
        case 25:    // CNF
          token->cnf = (char *) malloc(cbor_object->length);
          memcpy(token->cnf, cbor_object->v.str, cbor_object->length);
          printf("cnf found\n");
          token->in_cnf = 1;
          //parse_cwt_token(cbor_object->v.str, cbor_object->length);
          token->in_cnf = 0;
          break;
        case 7:     // CTI
          token->cti = (char *) malloc(cbor_object->length);
          memcpy(token->cti, cbor_object->v.str, cbor_object->length);
          printf("cti found\n");
          break;
        case 2:     // KID (inside CNF)
          token->kid = (char *) malloc(KEY_ID_LENGTH);
          printf("kid len is %d\n", cbor_object->length);
          memcpy(token->kid, cbor_object->v.str, cbor_object->length);
          printf("kid found\n");
          break;
        case -1:    // KEY (inside CNF)
          token->key = (char *) malloc(cbor_object->length);
          memcpy(token->key, cbor_object->v.str, cbor_object->length);
          printf("key found\n");
          break;
      }
      break;

    case CN_CBOR_TEXT:
      printf("Type is Text");
      printf("Current CLM: %d\n", *curr_claim);
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
      break;

    case CN_CBOR_UINT:
      printf("Type is Positive Int");
      printf("UINT: %lu\n", cbor_object->v.uint);
      if(cbor_object->v.uint < 256){
        *curr_claim = cbor_object->v.uint;
        printf("Found CLM: %d\n", *curr_claim);
      }
      else {
        switch(*curr_claim){
          case 4: token->exp = cbor_object->v.uint; break;
          case 5: token->nbf = cbor_object->v.uint; break;
          case 6: token->iat = cbor_object->v.uint; break;
        }
        *curr_claim = 0;
      }
      break;

    case CN_CBOR_INT:
      printf("Type is Negative Int");
      printf("NEGATIVE INT: %ld\n", cbor_object->v.sint);
      if(cbor_object->v.sint < 256){
        *curr_claim = cbor_object->v.sint;
        printf("Found CLM: %d\n", *curr_claim);
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
  char* nonce;
  //char key[KEY_LENGTH] = {0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  char key[KEY_LENGTH] = {0x7d, 0xd4, 0x43, 0x81, 0x1e, 0x32, 0x21, 0x08, 0x13, 0xc3, 0xc5, 0x11, 0x1e, 0x4d, 0x3d, 0xb4};

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

  // After the key id, there are 2 bytes indicating that the nonce is coming, and it size. We assume it will always be 13.
  int nonce_pos = key_id_pos + key_id_size + 2;
  printf("Getting nonce.\n");
  nonce = (char *) malloc(NONCE_SIZE);
  memcpy(nonce, &cbor_token[nonce_pos], NONCE_SIZE);

  // After the nonce there are 2 bytes indicating that a byte string is coming and its size.
  printf("Getting encrypted claims.\n");
  int encrypted_cbor_pos = nonce_pos + NONCE_SIZE + 2;
  int encrypted_cbor_length = token_length - encrypted_cbor_pos;
  char* encrypted_cbor = (char *) malloc(encrypted_cbor_length);
  memcpy(encrypted_cbor, &cbor_token[encrypted_cbor_pos], encrypted_cbor_length);

  printf("Decrypting claims.\n");
  unsigned char* decrypted_cbor = (unsigned char*) malloc(MAX_CBOR_CLAIMS_LEN);
  int decrypted_cbor_len = dtls_decrypt(encrypted_cbor, encrypted_cbor_length,
                                        decrypted_cbor, nonce, key, KEY_LENGTH, A_DATA, A_DATA_LEN);
  printf("%d bytes COSE decrypted\n", decrypted_cbor_len);
  //free(encrypted_cbor);

  printf("Decrypted CBOR:");
  int i;
  for (i=0; i < decrypted_cbor_len; i++){
    printf(" %02x", decrypted_cbor[i]);
  }
  printf("\n");

  printf("Decoding claims from CBOR bytes into CBOR object.\n");
  cn_cbor* cbor_claims = cn_cbor_decode(decrypted_cbor, decrypted_cbor_len CBOR_CONTEXT_PARAM, 0);
  if (claims) {
    printf("Parsing claims into cwt object.\n");
    cwt* token_info = (cwt*) malloc(sizeof(cwt));
    signed long curr_claim = 0;
    parse_claims(&curr_claim, token_info, cbor_claims);
    token_info->cbor_claims = decrypted_cbor;
    token_info->cbor_claims_length = decrypted_cbor_len;
    return token_info;
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
