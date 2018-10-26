#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"
#include "cbor-encode.h"

#define CBOR_PREFIX_MAP_HEADER_LENGTH 1

int encode_pair_to_cbor(int key, int int_value, const char* str_value, unsigned char** cbor_result);

// Encodes a map of 2 key-value pairs into CBOR. Keys are ints, values can be ints or strs.
int encode_map_to_cbor(int key1, int int_value1, const char* str_value1,
                       int key2, int int_value2, const char* str_value2, unsigned char** cbor_result) {
  // Map will have 2 pairs.
  unsigned char cbor_map_header = CBOR_PREFIX_MAP | 2;
  unsigned char* pair1_cbor = 0;
  int pair1_len = encode_pair_to_cbor(key1, int_value1, str_value1, &pair1_cbor);
  unsigned char* pair2_cbor = 0;
  int pair2_len = encode_pair_to_cbor(key2, int_value2, str_value2, &pair2_cbor);

  // Move both encoded bytes into a unified buffer.
  int cbor_bytes_len = CBOR_PREFIX_MAP_HEADER_LENGTH + pair1_len + pair2_len;
  printf("Encoding both pairs in map, total length %d.\n", cbor_bytes_len);
  *cbor_result = (unsigned char*) malloc(cbor_bytes_len);
  (*cbor_result)[0] = cbor_map_header;
  memcpy((*cbor_result) + CBOR_PREFIX_MAP_HEADER_LENGTH, pair1_cbor, pair1_len);
  memcpy((*cbor_result) + CBOR_PREFIX_MAP_HEADER_LENGTH + pair1_len, pair2_cbor, pair2_len);
  free(pair1_cbor);
  free(pair2_cbor);
  printf("Final encoded bytes: ");
  HEX_PRINTF((*cbor_result), cbor_bytes_len);

  return cbor_bytes_len;
}

// NOTE: We assume all ints, keys or values, will be less than 24, to simplify encoding.
int encode_pair_to_cbor(int key, int int_value, const char* str_value, unsigned char** cbor_result) {
  printf("Encoding pair to CBOR, with key %d, int value %d.\n", key, int_value);

  // Encode using the CBOR RFC rules. First key.
  int pos = 0;
  printf("Encoding key %d.\n", key);
  unsigned char* encoded_key;
  int encoded_key_len = encode_int_to_cbor(key, &encoded_key);

  // Now encode value.
  printf("Encoding value.\n");
  unsigned char* encoded_value;
  int encoded_value_len;
  if(str_value != 0) {
    encoded_value_len = encode_string_to_cbor(str_value, &encoded_value);
  }
  else {
    encoded_value_len = encode_int_to_cbor(int_value, &encoded_value);
  }

  // Put key and value contigously in a buffer.
  int encoded_len = encoded_key_len + encoded_value_len;
  printf("Encoding key and value together, total length %d.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);
  memcpy((*cbor_result), encoded_key, encoded_key_len);
  memcpy((*cbor_result) + encoded_key_len, encoded_value, encoded_value_len);
  free(encoded_key);
  free(encoded_value);

  printf("Encoded bytes: ");
  HEX_PRINTF((*cbor_result), encoded_len);

  return encoded_len;
}

// Takes an int and encodes it into CBOR bytes, returning the length in bytes.
// NOTE: We are not supporting ints larger than 23 here.
int encode_int_to_cbor(int int_value, unsigned char** cbor_result) {
  int encoded_len = 1;
  printf("Encoded int will use %d bytes.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);
  (*cbor_result)[0] = CBOR_PRFIX_INT | int_value;
  printf("Encoded int: ");
  HEX_PRINTF((*cbor_result), encoded_len);
  return encoded_len;
}

// Takes a string and coverts it to CBOR bytes, returning the CBOR length in bytes.
// NOTE: We are not supporting strings longer than 255 chars here (though it would be simple to extend).
int encode_string_to_cbor(const char* str_value, unsigned char** cbor_result) {
  // Encoded text strings will use 1 byte header, and maybe 1 more for length if 23 < length < 255.
  int encoded_len = 1;
  int str_value_len = strlen(str_value);
  if(str_value_len >= CBOR_ONE_BYTE_LIMIT) {
    encoded_len += 1;
  }
  encoded_len += str_value_len;

  printf("Encoded string will use %d bytes.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);

  int pos = 0;
  printf("Encoding string %s of length %d.\n", str_value, str_value_len);
  if(str_value_len < CBOR_ONE_BYTE_LIMIT) {
    printf("Adding 1 byte txt header.\n");
    (*cbor_result)[pos++] = CBOR_PREFIX_TXT | str_value_len;
  }
  else {
    printf("Adding 2 byte txt header.\n");
    (*cbor_result)[pos++] = CBOR_PREFIX_TXT | CBOR_ONE_BYTE_LIMIT;
    (*cbor_result)[pos++] = str_value_len;
  }

  // Now actually add the string.
  memcpy((*cbor_result) + pos, str_value, str_value_len);
  printf("Encoded string: ");
  HEX_PRINTF((*cbor_result), encoded_len);

  return encoded_len;
}
