#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "./cwt.h"

uint8_t* read_token(unsigned char *index, size_t idx_len,
         token_entry *result){
  char kid[17] = { 0 };
  char key[17] = { 0 };
  char *token_file = "tokens";
  int fd_read, file_size, file_pos;
  fd_read = cfs_open(token_file, CFS_READ);
  file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  printf("File size is %d\n", file_size);
  file_pos = cfs_seek(fd_read, 0, CFS_SEEK_SET);
  printf("Reading record identified by: %s\n", index);
  int i, j;
  i = 0;
  j = 0;
  char cbor_len[4] = { 0 };;
  while(i < file_size){
    i += cfs_read(fd_read, kid, 16);
    i += cfs_read(fd_read, key, 16);
    if (strncmp(index, kid, 16) == 0 ||
      strncmp(index, key, 16) == 0){
        printf("Matched!\n");
        result->kid = (char *) malloc(17);
        strncpy(result->kid, kid, 17);
        result->key = (char *) malloc(17);
        strncpy(result->key, key, 17);
        printf("Readed into struct key = %s\n", result->key);
        i += cfs_read(fd_read, cbor_len, 4);
        printf("Readed length kid into char pointer\n"); 
        j = atoi(cbor_len); 
        result->cbor = (char *) malloc(j+1);
      
        i += cfs_read(fd_read, result->cbor, j);
        printf("Readed cbor into struct\n"); 
    }
    printf("bytes read is %d\n", i);
    int k = cfs_seek(fd_read, 0, CFS_SEEK_CUR);
    printf("File position is %d\n", k);

  }
  if (j == 0)
  {
        printf("No matching entry\n");
  }
  return j;

}
