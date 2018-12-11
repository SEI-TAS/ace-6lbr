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
#define MAX_ENTRIES 20

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define HEX_PRINTF_DBG(byte_array, length) HEX_PRINTF(byte_array, length)
#else
#define PRINTF(...)
#define HEX_PRINTF_DBG(byte_array, length)
#endif

uint64_t bytes_to_uint64_t(unsigned char* bytes, int length);
unsigned char* uint64_t_to_bytes(uint64_t number);

void initialize_key_token_store() {
  printf("Creating keystore...\n");
  unsigned char pairing_key[KEY_LENGTH] = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  int fd_check_file = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  cfs_close(fd_check_file);
  if(fd_check_file == -1) {
    // File does not exist, let's create it with the pairing key.
    int bytes_written = 0;
    int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
    bytes_written += cfs_write(fd_write, PAIRING_KEY_ID, KEY_ID_LENGTH);
    bytes_written += cfs_write(fd_write, pairing_key, KEY_LENGTH);
    bytes_written += cfs_write(fd_write, NON_TOKEN_ENTRY_CBOR_LENGTH, CBOR_SIZE_LENGTH);
    printf("Stored default pairing key in tokens file.\n");
    cfs_close(fd_write);
  }
  else {
    printf("Won't create keystore, already exists.\n");
  }
}

// Writes an authz entry into the given open file.
void write_entry_to_file(authz_entry* entry, int fd_tokens_file) {
  // First write key id and key.
  int bytes_written = 0;
  PRINTF("Storing key id and key.\n");

  PRINTF("KID \n");
  HEX_PRINTF_DBG(entry->kid, KEY_ID_LENGTH);
  bytes_written += cfs_write(fd_tokens_file, entry->kid, KEY_ID_LENGTH);

  PRINTF("KEY: \n");
  HEX_PRINTF_DBG(entry->key, KEY_LENGTH);
  bytes_written += cfs_write(fd_tokens_file, entry->key, KEY_LENGTH);

  // Now write CBOR claims length, and the CBOR claims.
  PRINTF("Storing CBOR claims length.\n");
  char length_as_string[CBOR_SIZE_LENGTH + 1] = { 0 };
  snprintf(length_as_string, CBOR_SIZE_LENGTH + 1, "%0*d", CBOR_SIZE_LENGTH, entry->claims_len);
  PRINTF("Padded CBOR length: %s\n", length_as_string);
  bytes_written += cfs_write(fd_tokens_file, length_as_string, strlen(length_as_string));
  if(entry->claims_len > 0) {
    PRINTF("Storing CBOR claims.\n");
    bytes_written += cfs_write(fd_tokens_file, entry->claims, entry->claims_len);

    PRINTF("Storing received time.\n");
    unsigned char* time_buffer = uint64_t_to_bytes(entry->time_received_seconds);
    bytes_written += cfs_write(fd_tokens_file, time_buffer, sizeof(uint64_t));
    free(time_buffer);
  }

  return bytes_written;
}

// Stores the given token into the tokens file.
int store_authz_entry(authz_entry* entry) {
  printf("Storing pop key and token in token file.\n");
  int fd_tokens_file = cfs_open(TOKENS_FILE_NAME, CFS_APPEND);
  if(fd_tokens_file == -1){
    PRINTF("Could not open file to store key and token.");
    return 0;
  }

  int bytes_written = write_entry_to_file(entry, fd_tokens_file);

  cfs_close(fd_tokens_file);
  PRINTF("Finished storing pop key and token in token file. Wrote %d bytes.\n", bytes_written);
  return 1;
}

// Looks for an entry in the store, given the key id or key.
int find_authz_entry(const unsigned char* const index, size_t idx_len, authz_entry *result){
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
  HEX_PRINTF_DBG(index, idx_len);
  unsigned char kid[KEY_ID_LENGTH] = { 0 };
  unsigned char key[KEY_LENGTH] = { 0 };
  char claims_len_buffer[CBOR_SIZE_LENGTH + 1] = { 0 };
  int bytes_read = 0;
  int claims_len = 0;
  while(bytes_read < file_size) {
    bytes_read += cfs_read(fd_read, kid, KEY_ID_LENGTH);
    bytes_read += cfs_read(fd_read, key, KEY_LENGTH);
    bytes_read += cfs_read(fd_read, claims_len_buffer, CBOR_SIZE_LENGTH);
    claims_len = atoi(claims_len_buffer);

    PRINTF("Current key id: ");
    HEX_PRINTF_DBG(kid, KEY_ID_LENGTH);
    PRINTF("Current key: ");
    HEX_PRINTF_DBG(key, KEY_LENGTH);
    PRINTF("Current claims len: %d\n", claims_len);

    if (memcmp(index, kid, KEY_ID_LENGTH) == 0 || memcmp(index, key, KEY_LENGTH) == 0){
        PRINTF("Matched!\n");
        key_found = 1;

        result->kid = (unsigned char *) malloc(KEY_ID_LENGTH);
        memcpy(result->kid, kid, KEY_ID_LENGTH);
        result->kid[KEY_ID_LENGTH] = 0;

        result->key = (unsigned char *) malloc(KEY_LENGTH);
        memcpy(result->key, key, KEY_LENGTH);
        PRINTF("Readed into struct key: ");
        HEX_PRINTF_DBG(result->key, KEY_LENGTH);

        result->claims_len = claims_len;
        PRINTF("Claims len: %d\n", result->claims_len);

        if(result->claims_len > 0) {
          result->claims = (unsigned char *) malloc(result->claims_len);
          bytes_read += cfs_read(fd_read, result->claims, result->claims_len);
          PRINTF("Readed claims into struct: \n");
          HEX_PRINTF_DBG(result->claims, result->claims_len);

          unsigned char* received_time = (unsigned char *) malloc(sizeof(uint64_t));
          bytes_read += cfs_read(fd_read, received_time, sizeof(uint64_t));
          PRINTF("Readed received time into buffer: \n");
          HEX_PRINTF_DBG(received_time, sizeof(uint64_t));

          result->time_received_seconds = bytes_to_uint64_t(received_time, sizeof(uint64_t));
          PRINTF("Stored received time into struct: %lu\n", result->time_received_seconds);
        }
        else {
          result->claims = 0;
          result->time_received_seconds = 0;
          PRINTF("Record has no claim info associated to it.\n");
        }
    }
    else {
      if(claims_len > 0) {
        // We need to skip over the claims content and time to get to the next entry.
        cfs_seek(fd_read, claims_len, CFS_SEEK_CUR);
        bytes_read += claims_len;
        cfs_seek(fd_read, sizeof(uint64_t), CFS_SEEK_CUR);
        bytes_read += sizeof(uint64_t);
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
void free_authz_entry(authz_entry* entry) {
  if(entry->kid) {
    free(entry->kid);
  }
  if(entry->key) {
    free(entry->key);
  }
  if(entry->claims_len > 0) {
    free(entry->claims);
  }
}

// Removes the token for the given key id.
int remove_authz_entry(const unsigned char* const key_id, int key_id_len) {
  int success = 0;

  int fd_read = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  if(fd_read == -1) {
    PRINTF("ERROR: could not open tokens file '%s' for reading\n", TOKENS_FILE_NAME);
    return success;
  }

  int file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  PRINTF("File size is %d\n", file_size);
  cfs_seek(fd_read, 0, CFS_SEEK_SET);

  PRINTF("Looking for entry identified by key: ");
  HEX_PRINTF_DBG(key_id, key_id_len);

  int bytes_read = 0;
  int total_entries = 0;
  authz_entry* entry_list[MAX_ENTRIES] = {0};
  while(bytes_read < file_size) {
    if(total_entries == MAX_ENTRIES) {
      PRINTF("Max entries reached; removing rest of entries");
      break;
    }

    unsigned char* kid = (unsigned char*) malloc(KEY_ID_LENGTH);
    bytes_read += cfs_read(fd_read, kid, KEY_ID_LENGTH);
    PRINTF("Current key id: ");
    HEX_PRINTF_DBG(kid, KEY_ID_LENGTH);

    unsigned char* key = (unsigned char*) malloc(KEY_LENGTH);
    bytes_read += cfs_read(fd_read, key, KEY_LENGTH);

    char* claims_len_buffer = (char*) malloc(CBOR_SIZE_LENGTH + 1);
    bytes_read += cfs_read(fd_read, claims_len_buffer, CBOR_SIZE_LENGTH);
    claims_len_buffer[CBOR_SIZE_LENGTH] = 0;
    int claims_len = atoi(claims_len_buffer);

    if (memcmp(key_id, kid, KEY_ID_LENGTH) == 0){
        PRINTF("Ignoring token to remove!\n");
        // We need to skip over the key and claims size.
        if(claims_len > 0) {
          cfs_seek(fd_read, claims_len, CFS_SEEK_CUR);
          bytes_read += claims_len;
          cfs_seek(fd_read, sizeof(uint64_t), CFS_SEEK_CUR);
          bytes_read += sizeof(uint64_t);

          // Free the stored key id, key and claims size.
          free(kid);
          free(key);
          free(claims_len_buffer);
        }
        continue;
    }
    else {
      // Store this entry in memory so we can write it back to the file.
      authz_entry* current_entry = (authz_entry*) malloc(sizeof(authz_entry));
      current_entry->kid = kid;
      current_entry->key = key;
      current_entry->claims_len = claims_len;
      if(claims_len > 0) {
        // We still need to get the token info and time.
        unsigned char* claims = (unsigned char*) malloc(claims_len);
        bytes_read += cfs_read(fd_read, claims, claims_len);
        current_entry->claims = claims;

        unsigned char* received_time = (unsigned char *) malloc(sizeof(uint64_t));
        bytes_read += cfs_read(fd_read, received_time, sizeof(uint64_t));
        current_entry->time_received_seconds = bytes_to_uint64_t(received_time, sizeof(uint64_t));
      }

      entry_list[total_entries++] = current_entry;
    }

    PRINTF("bytes read is %d\n", bytes_read);
  }
  cfs_close(fd_read);

  // Now write them all but the removed one back to the file, removing what was in the file before.
  PRINTF("Re-writing all entries but the deleted one to file.");
  int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
  int curr_entry_num = 0;
  while(curr_entry_num < total_entries) {
    authz_entry* curr_entry = entry_list[curr_entry_num++];
    write_entry_to_file(curr_entry, fd_write);
  }
  cfs_close(fd_write);
  PRINTF("Finished re-writing all entries but the deleted one to file.");

  return success;
}

// Converts from byte array to uint64.
uint64_t bytes_to_uint64_t(unsigned char* bytes, int length){
  long value = 0;
  int i = 0;
  for (i = 0; i < length; i++) {
    value += ((long) bytes[i] & 0xffL) << (8 * i);
  }
  return value;
}

// Converts from uint64 to byte array.
unsigned char* uint64_t_to_bytes(uint64_t number){
  unsigned char* bytes = (unsigned char *) malloc(sizeof(uint64_t));
  int i = 0;
  for (i = 0; i < sizeof(uint64_t); i++) {
    bytes[i] = ((number >> (8 * i)) & 0xffL);
  }
  return bytes;
}