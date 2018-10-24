#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"


int find_token_entry(unsigned char* index, size_t idx_len, token_entry *result){
  int key_found = 0;

  int fd_read = cfs_open(TOKENS_FILE_NAME, CFS_READ);
  if(fd_read == -1) {
    printf("ERROR: could not open tokens file '%s' for reading\n", TOKENS_FILE_NAME);
    return key_found;
  }

  int file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  printf("File size is %d\n", file_size);
  cfs_seek(fd_read, 0, CFS_SEEK_SET);

  printf("Looking for record identified by: ");
  HEX_PRINTF(index, idx_len)
  unsigned char kid[KEY_ID_LENGTH] = { 0 };
  unsigned char key[KEY_LENGTH] = { 0 };
  char cbor_len_buffer[CBOR_SIZE_LENGTH + 1] = { 0 };
  int bytes_read = 0;
  while(bytes_read < file_size) {
    bytes_read += cfs_read(fd_read, kid, KEY_ID_LENGTH);
    bytes_read += cfs_read(fd_read, key, KEY_LENGTH);

    printf("Current key id: ");
    HEX_PRINTF(kid, KEY_ID_LENGTH)
    printf("Current key: ");
    HEX_PRINTF(key, KEY_LENGTH)

    if (memcmp(index, kid, KEY_ID_LENGTH) == 0 || memcmp(index, key, KEY_LENGTH) == 0){
        printf("Matched!\n");
        key_found = 1;

        result->kid = (unsigned char *) malloc(KEY_ID_LENGTH);
        memcpy(result->kid, kid, KEY_ID_LENGTH);
        result->kid[KEY_ID_LENGTH] = 0;

        result->key = (unsigned char *) malloc(KEY_LENGTH);
        memcpy(result->key, key, KEY_LENGTH);
        printf("Readed into struct key: ");
        HEX_PRINTF(result->key, KEY_LENGTH)

        bytes_read += cfs_read(fd_read, cbor_len_buffer, CBOR_SIZE_LENGTH);
        printf("Readed CBOR length into char pointer\n");
        int cbor_len = atoi(cbor_len_buffer);
        printf("Cbor len: %d\n", cbor_len);

        if(cbor_len > 0) {
          result->cbor = (unsigned char *) malloc(cbor_len);
          bytes_read += cfs_read(fd_read, result->cbor, cbor_len);
          printf("Readed cbor into struct: \n");
          HEX_PRINTF(result->cbor, cbor_len)
        }
        else {
          printf("Record has no CBOR info associated to it.\n");
        }
    }
    printf("bytes read is %d\n", bytes_read);
  }

  cfs_close(fd_read);
  if (key_found == 0)
  {
        printf("No matching entry\n");
  }
  return key_found;
}
