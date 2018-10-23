#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"


uint8_t* read_token(unsigned char *index, size_t idx_len,
         token_entry *result){
  char kid[KEY_ID_LENGTH + 1] = { 0 };
  char key[KEY_LENGTH + 1] = { 0 };

  char *token_file = "tokens";
  int fd_read = cfs_open(token_file, CFS_READ);
  int file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  printf("File size is %d\n", file_size);
  int file_pos = cfs_seek(fd_read, 0, CFS_SEEK_SET);
  printf("Looking for record identified by: %s\n", index);

  int bytes_read = 0;
  char cbor_len_buffer[4] = { 0 };
  int key_found = 0;
  while(bytes_read < file_size) {
    bytes_read += cfs_read(fd_read, kid, KEY_ID_LENGTH);
    bytes_read += cfs_read(fd_read, key, KEY_LENGTH);
    if (strncmp(index, kid, KEY_ID_LENGTH) == 0 ||
      strncmp(index, key, KEY_LENGTH) == 0){
        printf("Matched!\n");
        key_found = 1;

        result->kid = (char *) malloc(KEY_ID_LENGTH + 1);
        memcpy(result->kid, kid, KEY_ID_LENGTH);
        result->kid[KEY_ID_LENGTH] = 0;

        result->key = (char *) malloc(KEY_LENGTH);
        memcpy(result->key, key, KEY_LENGTH);
        printf("Readed into struct key: ");
        int i;
        for (i=0; i<KEY_LENGTH; i++){
          printf(" %x",result->key[i]);
        }
        printf("\n");

        bytes_read += cfs_read(fd_read, cbor_len_buffer, CBOR_SIZE_LENGTH);
        printf("Readed length kid into char pointer\n"); 
        int cbor_len = atoi(cbor_len_buffer);
        printf("Cbor len: %d\n", cbor_len);

        result->cbor = (char *) malloc(cbor_len + 1);
        bytes_read += cfs_read(fd_read, result->cbor, cbor_len);
        result->cbor[cbor_len] = 0;
        printf("Readed cbor into struct: %s\n", result->cbor);
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
