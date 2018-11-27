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
#include "cfs/cfs.h"

#include "cwt.h"
#include "key-token-store.h"
#include "utils.h"

#define TOKENS_FILE_NAME "tokens"

#define PAIRING_KEY_ID "Authentication01"
#define NON_TOKEN_ENTRY_CBOR_LENGTH "0000"

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#define HEX_PRINTF(byte_array, length)
#endif


void initialize_key_token_store() {
  printf("Creating keystore...\n");
  //char pairing_key[32] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x52, 0x53, 0x31, 0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  unsigned char pairing_key[KEY_LENGTH] = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  //unsigned char test_key[KEY_LENGTH] = {0x7d, 0xd4, 0x43, 0x81, 0x1e, 0x32, 0x21, 0x08, 0x13, 0xc3, 0xc5, 0x11, 0x1e, 0x4d, 0x3d, 0xb4};
  //unsigned char test_key_id[3] = {'R', 'S', '2'};
  //unsigned char* padded_test_key_id = left_pad_array(test_key_id, 3, KEY_ID_LENGTH, 0);

  int fd_check_file = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  if(fd_check_file == -1) {
    // File does not exist, let's create it with the pairing key.
    int bytes_written = 0;
    int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
    bytes_written += cfs_write(fd_write, PAIRING_KEY_ID, KEY_ID_LENGTH);
    bytes_written += cfs_write(fd_write, pairing_key, KEY_LENGTH);
    bytes_written += cfs_write(fd_write, NON_TOKEN_ENTRY_CBOR_LENGTH, CBOR_SIZE_LENGTH);
    printf("Stored default pairing key in tokens file.\n");

    //bytes_written += cfs_write(fd_write, padded_test_key_id, KEY_ID_LENGTH);
    //bytes_written += cfs_write(fd_write, test_key, KEY_LENGTH);
    //bytes_written += cfs_write(fd_write, NON_TOKEN_ENTRY_CBOR_LENGTH, CBOR_SIZE_LENGTH);
    //PRINTF("Stored test paired key in tokens file, wrote %d bytes.\n", bytes_written);

    cfs_close(fd_write);
  }
  else {
    printf("Won't create keystore, already exists.\n");
    cfs_close(fd_check_file);
  }
}

// Stores the given token into the tokens file.
int store_token(cwt* token) {
  printf("Storing pop key and token in token file.\n");
  int bytes_written = 0;
  int fd_tokens_file = cfs_open(TOKENS_FILE_NAME, CFS_WRITE | CFS_APPEND);
  if(fd_tokens_file != -1){
    // First write key id and key.
    PRINTF("Storing key id and key.\n");
    unsigned char* padded_id = left_pad_array(token->kid, token->kid_len, KEY_ID_LENGTH, 0);
    PRINTF("Padded KID: \n");
    HEX_PRINTF(padded_id, KEY_ID_LENGTH);
    bytes_written += cfs_write(fd_tokens_file, padded_id, KEY_ID_LENGTH);
    //free(padded_id);
    PRINTF("KEY: \n");
    HEX_PRINTF(token->key, KEY_LENGTH);
    bytes_written += cfs_write(fd_tokens_file, token->key, KEY_LENGTH);

    // Now write CBOR claims length, and the CBOR claims.
    PRINTF("Storing CBOR claims length.\n");
    char length_as_string[CBOR_SIZE_LENGTH + 1] = { 0 };
    snprintf(length_as_string, CBOR_SIZE_LENGTH + 1, "%0*d", CBOR_SIZE_LENGTH, token->cbor_claims_len);
    PRINTF("Padded CBOR length: %s\n", length_as_string);
    bytes_written += cfs_write(fd_tokens_file, length_as_string, strlen(length_as_string));
    if(token->cbor_claims_len > 0) {
      PRINTF("Storing CBOR claims.\n");
      bytes_written += cfs_write(fd_tokens_file, token->cbor_claims, token->cbor_claims_len);
    }

    cfs_close(fd_tokens_file);
    printf("Finished storing pop key and token in token file. Wrote %d bytes.\n", bytes_written);
    return 1;
  }
  else {
    return 0;
  }
}

// Looks for an entry in the store, given the key id or key.
int find_token_entry(const unsigned char* const index, size_t idx_len, token_entry *result){
  int key_found = 0;

  int fd_read = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  if(fd_read == -1) {
    PRINTF("ERROR: could not open tokens file '%s' for reading\n", TOKENS_FILE_NAME);
    return key_found;
  }

  int file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  PRINTF("File size is %d\n", file_size);
  cfs_seek(fd_read, 0, CFS_SEEK_SET);

  PRINTF("Looking for record identified by: ");
  HEX_PRINTF(index, idx_len)
  unsigned char kid[KEY_ID_LENGTH] = { 0 };
  unsigned char key[KEY_LENGTH] = { 0 };
  char cbor_len_buffer[CBOR_SIZE_LENGTH + 1] = { 0 };
  int bytes_read = 0;
  int curr_size = 0;
  while(bytes_read < file_size) {
    bytes_read += cfs_read(fd_read, kid, KEY_ID_LENGTH);
    bytes_read += cfs_read(fd_read, key, KEY_LENGTH);
    bytes_read += cfs_read(fd_read, cbor_len_buffer, CBOR_SIZE_LENGTH);
    curr_size = atoi(cbor_len_buffer);

    PRINTF("Current key id: ");
    HEX_PRINTF(kid, KEY_ID_LENGTH);
    PRINTF("Current key: ");
    HEX_PRINTF(key, KEY_LENGTH);
    PRINTF("Current cbor len: %d\n", curr_size);

    if (memcmp(index, kid, KEY_ID_LENGTH) == 0 || memcmp(index, key, KEY_LENGTH) == 0){
        PRINTF("Matched!\n");
        key_found = 1;

        result->kid = (unsigned char *) malloc(KEY_ID_LENGTH);
        memcpy(result->kid, kid, KEY_ID_LENGTH);
        result->kid[KEY_ID_LENGTH] = 0;

        result->key = (unsigned char *) malloc(KEY_LENGTH);
        memcpy(result->key, key, KEY_LENGTH);
        PRINTF("Readed into struct key: ");
        HEX_PRINTF(result->key, KEY_LENGTH)

        result->cbor_len = curr_size;
        PRINTF("Cbor len: %d\n", result->cbor_len);

        if(result->cbor_len > 0) {
          result->cbor = (unsigned char *) malloc(result->cbor_len);
          bytes_read += cfs_read(fd_read, result->cbor, result->cbor_len);
          PRINTF("Readed cbor into struct: \n");
          HEX_PRINTF(result->cbor, result->cbor_len)
        }
        else {
          result->cbor = 0;
          PRINTF("Record has no CBOR info associated to it.\n");
        }
    }
    else {
      if(curr_size > 0) {
        // We need to skip over the cbor content to get to the next entry.
        cfs_seek(fd_read, curr_size, CFS_SEEK_CUR);
        bytes_read += curr_size;
      }
    }

    PRINTF("bytes read is %d\n", bytes_read);
  }

  cfs_close(fd_read);
  if (key_found == 0)
  {
    PRINTF("No matching entry\n");
  }
  return key_found;
}

// Frees a generated token entry.
void free_token_entry(token_entry* entry) {
  if(entry->kid) {
    free(entry->kid);
  }
  if(entry->key) {
    free(entry->key);
  }
  if(entry->cbor_len > 0) {
    free(entry->cbor);
  }
}
