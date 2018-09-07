#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"

uint8_t* read_token(unsigned char *index, size_t idx_len,
         token_entry *result){
  char line[256];
  line[255] = 0;
  char kid[17];
  kid[16] = 0;
  char key[17];
  key[16] = 0;
  char *token_file = "tokens";
  int fd_read, file_size, file_pos;
  fd_read = cfs_open(token_file, CFS_READ);
  file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  printf("File size is %d\n", file_size);
  file_pos = cfs_seek(fd_read, 0, CFS_SEEK_SET);
  printf("Reading record identified by: %s\n", index);
  int i, cbor_len;
  i = 0;
  cbor_len = 0;
  while(i <= file_size){
    cfs_read(fd_read, kid, 16);
    cfs_read(fd_read, key, 16);
    if (strncmp(index, kid, 16) == 0 ||
      strncmp(index, key, 16) == 0){
        result->kid = kid;
        result->key = key;
        cfs_read(fd_read, cbor_len, 4);
        cfs_read(fd_read, result->cbor, cbor_len);
        i = cfs_seek(fd_read, 0, CFS_SEEK_CUR);
    }

  }
  if (cbor_len == 0)
  {
        printf("No matching entry\n");
  }
  return cbor_len;

}