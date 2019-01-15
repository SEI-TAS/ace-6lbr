/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "cbor-encode.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define HEX_PRINTF_INL(byte_array, length) HEX_PRINTF(byte_array, length)
#else
#define PRINTF(...)
#define HEX_PRINTF_INL(byte_array, length)
#endif

int encode_pair_to_cbor(int key, int int_value, const char* bytes_value, int bytes_value_len, unsigned char** cbor_result);

// Encodes a map of 2 key-value pairs into CBOR. Keys are ints, values can be ints or strs.
int encode_map_to_cbor(int key1, int int_value1, const char* str_value1,
                       int key2, int int_value2, const char* str_value2, unsigned char** cbor_result) {
  // Map will have 2 pairs.
  int number_of_pairs = 2;
  unsigned char cbor_map_header = CBOR_PREFIX_MAP | number_of_pairs;
  unsigned char* pair1_cbor = 0;
  int pair1_len = encode_pair_to_cbor(key1, int_value1, str_value1, strlen(str_value1), &pair1_cbor);
  unsigned char* pair2_cbor = 0;
  int pair2_len = encode_pair_to_cbor(key2, int_value2, str_value2, strlen(str_value2), &pair2_cbor);

  // Move both encoded bytes into a unified buffer.
  int cbor_bytes_len = sizeof(cbor_map_header) + pair1_len + pair2_len;
  PRINTF("Encoding both pairs in map, total length %d.\n", cbor_bytes_len);
  *cbor_result = (unsigned char*) malloc(cbor_bytes_len);
  (*cbor_result)[0] = cbor_map_header;
  memcpy((*cbor_result) + sizeof(cbor_map_header), pair1_cbor, pair1_len);
  memcpy((*cbor_result) + sizeof(cbor_map_header) + pair1_len, pair2_cbor, pair2_len);
  free(pair1_cbor);
  free(pair2_cbor);
  PRINTF("Final encoded bytes: ");
  HEX_PRINTF_INL((*cbor_result), cbor_bytes_len);

  return cbor_bytes_len;
}

// Encodes a map of 1 key-value pair into CBOR. Key is int, value is a byte array.
// NOTE: We assume all ints, keys or values, will be less than 24, to simplify encoding.
int encode_single_pair_to_cbor_map(int key, const unsigned char* value, int value_len, unsigned char** cbor_result) {
  int number_of_pairs = 1;
  unsigned char cbor_map_header = CBOR_PREFIX_MAP | number_of_pairs;

  unsigned char* pair1_cbor = 0;
  int pair1_len = encode_pair_to_cbor(key, 0, (const unsigned char*) value, value_len, &pair1_cbor);

  int cbor_bytes_len = sizeof(cbor_map_header) + pair1_len;
  PRINTF("Encoding pair in map, total length %d.\n", cbor_bytes_len);
  *cbor_result = (unsigned char*) malloc(cbor_bytes_len);
  (*cbor_result)[0] = cbor_map_header;
  memcpy((*cbor_result) + sizeof(cbor_map_header), pair1_cbor, pair1_len);
  free(pair1_cbor);
  PRINTF("Final encoded bytes: ");
  HEX_PRINTF_INL((*cbor_result), cbor_bytes_len);

  return cbor_bytes_len;
}

// NOTE: We assume all ints, keys or values, will be less than 24, to simplify encoding.
int encode_pair_to_cbor(int key, int int_value, const char* bytes_value, int bytes_value_len, unsigned char** cbor_result) {
  PRINTF("Encoding pair to CBOR, with key %d, int value %d.\n", key, int_value);

  // Encode using the CBOR RFC rules. First key.
  PRINTF("Encoding key %d.\n", key);
  unsigned char* encoded_key;
  int encoded_key_len = encode_int_to_cbor(key, &encoded_key);

  // Now encode value.
  PRINTF("Encoding value.\n");
  unsigned char* encoded_value;
  int encoded_value_len;
  if(bytes_value != 0) {
    encoded_value_len = encode_bytes_to_cbor(bytes_value, bytes_value_len, &encoded_value);
  }
  else {
    encoded_value_len = encode_int_to_cbor(int_value, &encoded_value);
  }

  // Put key and value contigously in a buffer.
  int encoded_len = encoded_key_len + encoded_value_len;
  PRINTF("Encoding key and value together, total length %d.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);
  memcpy((*cbor_result), encoded_key, encoded_key_len);
  memcpy((*cbor_result) + encoded_key_len, encoded_value, encoded_value_len);
  free(encoded_key);
  free(encoded_value);

  PRINTF("Encoded bytes: ");
  HEX_PRINTF_INL((*cbor_result), encoded_len);

  return encoded_len;
}

// Takes an int and encodes it into CBOR bytes, returning the length in bytes.
// NOTE: We are not supporting ints larger than 23 here.
int encode_int_to_cbor(int int_value, unsigned char** cbor_result) {
  int encoded_len = 1;
  PRINTF("Encoded int will use %d bytes.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);
  (*cbor_result)[0] = CBOR_PRFIX_INT | int_value;
  PRINTF("Encoded int: ");
  HEX_PRINTF_INL((*cbor_result), encoded_len);
  return encoded_len;
}

// Takes a byte array and coverts it to CBOR bytes, returning the CBOR length in bytes.
// NOTE: We are not supporting byte arrays longer than 255 chars here (though it would be simple to extend).
int encode_bytes_to_cbor(const char* input_array, int input_array_len, unsigned char** cbor_result) {
  // Encoded byte arrays will use 1 byte header, and maybe 1 more for length if 23 < length < 255.
  int encoded_len = 1;
  if(input_array_len >= CBOR_ONE_BYTE_LIMIT) {
    encoded_len += 1;
  }
  encoded_len += input_array_len;
  PRINTF("Encoded bytes will use %d bytes.\n", encoded_len);

  PRINTF("Encoding byte array of length %d, contents: ", input_array_len);
  HEX_PRINTF_INL(input_array, input_array_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);
  int pos = 0;
  if(input_array_len < CBOR_ONE_BYTE_LIMIT) {
    PRINTF("Adding 1 byte txt header.\n");
    (*cbor_result)[pos++] = CBOR_PREFIX_TXT | input_array_len;
  }
  else {
    PRINTF("Adding 2 byte txt header.\n");
    (*cbor_result)[pos++] = CBOR_PREFIX_TXT | CBOR_ONE_BYTE_LIMIT;
    (*cbor_result)[pos++] = input_array_len;
  }

  // Now actually add the string.
  memcpy((*cbor_result) + pos, input_array, input_array_len);
  PRINTF("Encoded byte array: ");
  HEX_PRINTF_INL((*cbor_result), encoded_len);

  return encoded_len;
}
