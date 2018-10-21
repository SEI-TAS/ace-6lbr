#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "keystore.h"
#include "dtls.h"
#include "dtls_debug.h"

#define DEFAULT_KEY_SIZE 40

void keystore_init(){
  dtls_debug("Creating keystore...\n");
  /* char line[32] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x52, 0x53, 0x31, 0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}; */
  char line[DEFAULT_KEY_SIZE] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD0004test";
  char *token_file = "tokens";
  int fd_write, n;
  fd_write = cfs_open(token_file, CFS_WRITE);
  if(fd_write != -1){
    n = cfs_write(fd_write, line, DEFAULT_KEY_SIZE);
    cfs_close(fd_write);
  }

}

