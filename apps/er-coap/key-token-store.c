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
#define HEX_PRINTF_DBG(byte_array, length) HEX_PRINTF(byte_array, length)
#else
#define PRINTF(...)
#define HEX_PRINTF_DBG(byte_array, length)
#endif

/*--------------------------------------------------------------------*/
// Private utility functions.

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

// Adds the given value as padding to the left of the array.
unsigned char* left_pad_array(const unsigned char* const byte_array, int array_length, int final_length, char padding) {
  unsigned char* padded_array = (unsigned char *) malloc(final_length);
  memset(padded_array, padding, final_length);
  int padding_len = final_length - array_length;
  memcpy(&padded_array[padding_len], byte_array, array_length);
  return padded_array;
}

/*--------------------------------------------------------------------*/
// Private read and write single entry functions.

// Writes an authz entry into the given open file.
int write_entry_to_file(authz_entry* entry, int fd_tokens_file) {
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

// Reads and loads the next authz_entry object from file, returning the bytes read.
int read_entry_from_file(authz_entry** entry, int fd_tokens_file) {
  PRINTF("Reading entry from file.\n");
  int bytes_read = 0;

  unsigned char* kid = (unsigned char *) malloc(KEY_ID_LENGTH);
  bytes_read += cfs_read(fd_tokens_file, kid, KEY_ID_LENGTH);
  PRINTF("Key id: ");
  HEX_PRINTF_DBG(kid, KEY_ID_LENGTH);

  unsigned char* key = (unsigned char *) malloc(KEY_LENGTH);
  bytes_read += cfs_read(fd_tokens_file, key, KEY_LENGTH);
  PRINTF("Key: ");
  HEX_PRINTF_DBG(key, KEY_LENGTH);

  char claims_len_buffer[CBOR_SIZE_LENGTH + 1] = { 0 };
  bytes_read += cfs_read(fd_tokens_file, claims_len_buffer, CBOR_SIZE_LENGTH);
  int claims_len = atoi(claims_len_buffer);
  PRINTF("Claims len: %d\n", claims_len);

  unsigned char* claims = 0;
  uint64_t time_received_seconds = 0;
  if(claims_len > 0) {
    claims = (unsigned char *) malloc(claims_len);
    bytes_read += cfs_read(fd_tokens_file, claims, claims_len);
    PRINTF("Claims: \n");
    HEX_PRINTF_DBG(claims, claims_len);

    unsigned char* received_time = (unsigned char *) malloc(sizeof(uint64_t));
    bytes_read += cfs_read(fd_tokens_file, received_time, sizeof(uint64_t));
    time_received_seconds = bytes_to_uint64_t(received_time, sizeof(uint64_t));
    PRINTF("Received time: %lu\n", (unsigned long int) time_received_seconds);
    free(received_time);
  }
  else {
    PRINTF("Record has no claim info associated to it.\n");
  }

  (*entry) = create_authz_entry(kid, KEY_ID_LENGTH, key, claims_len, claims, time_received_seconds);
  return bytes_read;
}

/*--------------------------------------------------------------------*/
// Public functions.

// Initialization of storage.
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

// Constructor-like function. Ensures KID is paddded to size.
authz_entry* create_authz_entry(unsigned char* kid, int kid_len, unsigned char* key, int claims_len, unsigned char* claims, uint64_t time) {
  authz_entry* authz_info = (authz_entry*) malloc(sizeof(authz_entry));
  authz_info->kid = left_pad_array(kid, kid_len, KEY_ID_LENGTH, 0);
  authz_info->key = key;
  authz_info->claims_len = claims_len;
  authz_info->claims = claims;
  authz_info->time_received_seconds = time;
  return authz_info;
}

// Stores the given token into the tokens file.
int store_authz_entry(authz_entry* entry) {
  printf("Storing pop key and token in token file.\n");
  int fd_tokens_file = cfs_open(TOKENS_FILE_NAME, CFS_WRITE | CFS_APPEND);
  if(fd_tokens_file == -1){
    PRINTF("Could not open file to store key and token.\n");
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

  authz_entry_iterator iterator = authz_entry_iterator_initialize();

  unsigned char* padded_idx = left_pad_array(index, idx_len, KEY_ID_LENGTH, 0);
  PRINTF("Looking for record identified by: ");
  HEX_PRINTF_DBG(padded_idx, KEY_ID_LENGTH);

  // Loop over all entries until we find one with the given KID.
  result->kid = 0;
  authz_entry* curr_entry = authz_entry_iterator_get_next(&iterator);
  while(curr_entry != 0) {
    if (memcmp(padded_idx, curr_entry->kid, KEY_ID_LENGTH) == 0){
        PRINTF("Found match!\n");
        key_found = 1;

        // If we had already found a previous token, free its memory from the result param.
        if(result->kid != 0) {
          free_authz_entry(result);
        }

        // Copy the entry to the result param.
        PRINTF("Copying data to output param.\n");
        result->kid = curr_entry->kid;
        result->key = curr_entry->key;
        result->claims = curr_entry->claims;
        result->claims_len = curr_entry->claims_len;
        result->time_received_seconds = curr_entry->time_received_seconds;
    }
    else {
      free_authz_entry(curr_entry);
    }

    PRINTF("Freeing resources.\n");
    free(curr_entry);

    PRINTF("Moving to next item.\n");
    curr_entry = authz_entry_iterator_get_next(&iterator);
  }

  PRINTF("Freeing iterator and padded idx.\n");
  authz_entry_iterator_finish(iterator);
  free(padded_idx);

  if (key_found == 0)
  {
    PRINTF("No matching entry\n");
  }

  PRINTF("Returning from find\n");
  return key_found;
}

// Frees the inner data of a  generated entry.
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

// Removes the tokens for the given key ids. Assumption is that all key ids are of length KEY_ID_LENGTH.
int remove_authz_entries(authz_entry* key_id_list[], int key_id_list_len) {
  int number_of_removed_tokens = 0;

  authz_entry_iterator iterator = authz_entry_iterator_initialize();

  // Loop over all entries, adding all of them but the one we want to remove to an array.
  int total_entries = 0;
  authz_entry* entry_list[MAX_AUTHZ_ENTRIES] = {0};
  authz_entry* curr_entry = authz_entry_iterator_get_next(&iterator);
  while(curr_entry != 0) {
    if(total_entries == MAX_AUTHZ_ENTRIES) {
      PRINTF("Max entries reached; removing rest of entries\n");
      break;
    }

    // Loop over all the tokens to delete to see if this is one of them.
    int i = 0;
    for(i = 0; i < key_id_list_len; i++) {
      if (memcmp(key_id_list[i]->kid, curr_entry->kid, KEY_ID_LENGTH) == 0){
        PRINTF("Token to remove found; identified by key id: ");
        HEX_PRINTF_DBG(curr_entry->kid, KEY_ID_LENGTH);
        number_of_removed_tokens++;
        free_authz_entry(curr_entry);
        free(curr_entry);
        continue;
      }
      else {
        entry_list[total_entries++] = curr_entry;
      }
    }

    curr_entry = authz_entry_iterator_get_next(&iterator);
  }

  authz_entry_iterator_finish(iterator);

  // Now write them all but the removed one back to the file, removing what was in the file before.
  PRINTF("Re-writing all entries but the deleted one to file.\n");
  int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
  int curr_entry_num = 0;
  while(curr_entry_num < total_entries) {
    authz_entry* curr_entry = entry_list[curr_entry_num++];
    write_entry_to_file(curr_entry, fd_write);
    free_authz_entry(curr_entry);
    free(curr_entry);
  }
  cfs_close(fd_write);
  PRINTF("Finished re-writing all entries but the deleted one to file.\n");

  return number_of_removed_tokens;
}

/*--------------------------------------------------------------------*/
// Authz entry iterator.

// Reset iterator to reopen file when needed.
void authz_entry_iterator_reopen(authz_entry_iterator* iterator) {
  if(iterator->entry_file_fd == -1) {
    iterator->entry_file_fd = cfs_open(TOKENS_FILE_NAME, CFS_READ);
    if(iterator->entry_file_fd == -1) {
      PRINTF("ERROR: could not reopen tokens file '%s' for reading\n", TOKENS_FILE_NAME);
      return;
    }
    cfs_seek(iterator.entry_file_fd, iterator->curr_pos, CFS_SEEK_SET);
  }
}

// Initialize iterator, opening file.
authz_entry_iterator authz_entry_iterator_initialize() {
  authz_entry_iterator iterator;
  iterator.entry_file_fd = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  if(iterator.entry_file_fd == -1) {
    PRINTF("ERROR: could not open tokens file '%s' for reading\n", TOKENS_FILE_NAME);
    return iterator;
  }

  iterator.file_size = cfs_seek(iterator.entry_file_fd, 0, CFS_SEEK_END);
  PRINTF("File size is %d\n", iterator.file_size);
  cfs_seek(iterator.entry_file_fd, 0, CFS_SEEK_SET);
  iterator.curr_pos = 0;

  return iterator;
}

// Clear up global variables, including closing file.
void authz_entry_iterator_finish(authz_entry_iterator iterator) {
  cfs_close(iterator.entry_file_fd);
  iterator.entry_file_fd = -1;
}

// Get next entry from file.
authz_entry* authz_entry_iterator_get_next(authz_entry_iterator* iterator) {
  if(iterator->curr_pos < iterator->file_size) {
    authz_entry* curr_entry;
    iterator->curr_pos += read_entry_from_file(&curr_entry, iterator->entry_file_fd);
    return curr_entry;
  }
  else {
    // No more entries in file.
    return 0;
  }
}