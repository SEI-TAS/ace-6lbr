#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"


uint8_t* lookup_dtls_key(unsigned char *id, size_t id_len,
         uint8_t *result, size_t result_length){
  char line[33];
  line[32] = 0;
  char key[17];
  key[16] = 0;
  char *token_file = "tokens";
  int fd_read, file_size, file_pos;
  fd_read = cfs_open(token_file, CFS_READ);
  file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  printf("File size is %d\n", file_size);
  file_pos = cfs_seek(fd_read, 0, CFS_SEEK_SET);
  printf("In lookup id: %s\n", id);
  int i;
  for(i=1; i <= file_size/32; i++){
    cfs_read(fd_read, line, 32);
    memcpy(key, &line[0], 16);
    printf("My Key is %s\n",key);
    if (strncmp(id,key,16) == 0){
      memcpy(result, &line[16], 16);
      printf("Result is %x\n", result);
    }else{
      printf("No matching key\n");
    }
    file_pos = cfs_seek(fd_read, 32, CFS_SEEK_CUR);
  }

}
