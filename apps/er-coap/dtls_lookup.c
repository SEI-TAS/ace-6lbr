#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"


uint8_t* lookup_dtls_key(unsigned char *id, size_t id_len,
         uint8_t *result, size_t result_length){
  char line[32];
  char *token_file = "tokens";
  int fd_read, file_size, file_pos;
  fd_read = cfs_open(token_files, CFS_READ);
  file_size = cfs_seek(fd_read, 0, CFS_SEEK_END);
  file_pos = cfs_seek(fd_read, 0, CFS_SEEK_SET);
  int i;
  while(i=1; i < file_size/32; i++){
    cfs_read(fd_read, line, 32);
    if ([1ST HALF OF LINE] == id){
      result = [2ND HALF OF LINE]
    }
  file_pos = cfs_seek(fd_read, 32, CFS_SEEK_CURR);
  }

}
