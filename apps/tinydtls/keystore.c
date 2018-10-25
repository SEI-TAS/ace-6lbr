#include "contiki.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cfs/cfs.h"
#include "keystore.h"
#include "dtls.h"
#include "dtls_debug.h"
#include "cwt.h"

#define PAIRING_KEY_ID "Authentication01"
#define NON_TOKEN_ENTRY_CBOR_LENGTH "0000"

void keystore_init(){
  dtls_debug("Creating keystore...\n");
  //char pairing_key[32] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x52, 0x53, 0x31, 0xa1, 0xa2, 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  unsigned char pairing_key[KEY_LENGTH] = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  //unsigned char test_key[KEY_LENGTH] = {0x7d, 0xd4, 0x43, 0x81, 0x1e, 0x32, 0x21, 0x08, 0x13, 0xc3, 0xc5, 0x11, 0x1e, 0x4d, 0x3d, 0xb4};
  //unsigned char test_key_id[3] = {'R', 'S', '2'};
  //unsigned char* padded_test_key_id = left_pad_array(test_key_id, 3, KEY_ID_LENGTH, 0);

  int bytes_written = 0;
  int fd_write = cfs_open(TOKENS_FILE_NAME, CFS_WRITE);
  if(fd_write != -1){
    bytes_written += cfs_write(fd_write, PAIRING_KEY_ID, KEY_ID_LENGTH);
    bytes_written += cfs_write(fd_write, pairing_key, KEY_LENGTH);
    bytes_written += cfs_write(fd_write, NON_TOKEN_ENTRY_CBOR_LENGTH, CBOR_SIZE_LENGTH);
    dtls_debug("Stored default pairing key in tokens file.\n");

    //bytes_written += cfs_write(fd_write, padded_test_key_id, KEY_ID_LENGTH);
    //bytes_written += cfs_write(fd_write, test_key, KEY_LENGTH);
    //bytes_written += cfs_write(fd_write, NON_TOKEN_ENTRY_CBOR_LENGTH, CBOR_SIZE_LENGTH);
    //dtls_debug("Stored test paired key in tokens file, wrote %d bytes.\n", bytes_written);

    cfs_close(fd_write);
  }
  else {
    dtls_debug("Could not open tokens file to initialize it with default pairing key.\n");
  }

}

