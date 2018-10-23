#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "keystore.h"
#include "dtls.h"
#include "dtls_debug.h"
#include "cwt.h""

#define PAIRING_KEY_ID "Authentication01"
#define PAIRING_KEY_TOKEN_LENGTH "0000"

void keystore_init(){
  dtls_debug("Creating keystore...\n");
  //char pairing_key[32] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x52, 0x53, 0x31, 0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  char pairing_key[KEY_SIZE_BYTES] = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  int bytes_written;
  int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
  if(fd_write != -1){
    bytes_written = cfs_write(fd_write, PAIRING_KEY_ID, strlen(PAIRING_KEY_ID));
    bytes_written = cfs_write(fd_write, pairing_key, KEY_LENGTH);
    bytes_written = cfs_write(fd_write, PAIRING_KEY_TOKEN_LENGTH, strlen(PAIRING_KEY_TOKEN_LENGTH));
    dtls_debug("Stored default pairing key in tokens file.\n");
    cfs_close(fd_write);
  }
  else {
    dtls_debug("Could not open tokens file to initialize it with default pairing key.\n");
  }

}

