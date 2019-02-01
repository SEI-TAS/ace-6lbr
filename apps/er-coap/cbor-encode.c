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

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define HEX_PRINTF_INL(byte_array, length) HEX_PRINTF(byte_array, length)
#else
#define PRINTF(...)
#define HEX_PRINTF_INL(byte_array, length)
#endif

//---------------------------------------------------------------------------------------------
// Encodes a pair, assuming an int key, and a value that can be either an int, or a byte string, or a text string.
// NOTE: We assume all ints (keys or values) will be less than 255, to simplify encoding.
static
int encode_pair_to_cbor(int key, int int_value, const unsigned char* bytes_value, const char* txt_value, int value_len, unsigned char** cbor_result) {
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
    encoded_value_len = encode_bytes_to_cbor(bytes_value, value_len, &encoded_value);
  }
  else if(txt_value != 0) {
    encoded_value_len = encode_string_to_cbor(txt_value, value_len, &encoded_value);
  }
  else {
    encoded_value_len = encode_int_to_cbor(int_value, &encoded_value);
  }

  // Put key and value contiguously in a buffer.
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

//---------------------------------------------------------------------------------------------
// NOTE: we assume we won't get more than 23 pairs.
static
int encode_map_to_cbor(unsigned char* pairs[], int pairs_lengths[], int number_of_pairs, unsigned char** cbor_result) {
  // Header.
  unsigned char cbor_map_header = CBOR_PREFIX_MAP | number_of_pairs;
  int header_len = sizeof(cbor_map_header);

  // Calculcate total length.
  int cbor_bytes_len = header_len;
  int i = 0;
  for(i = 0; i < number_of_pairs; i++) {
    cbor_bytes_len += pairs_lengths[i];
  }

  // Merge all pairs.
  PRINTF("Encoding pairs in map, total length %d.\n", cbor_bytes_len);
  *cbor_result = (unsigned char*) malloc(cbor_bytes_len);
  (*cbor_result)[0] = cbor_map_header;
  int pos = header_len;
  for(i = 0; i < number_of_pairs; i++) {
    memcpy((*cbor_result) + pos, pairs[i], pairs_lengths[i]);
    pos += pairs_lengths[i];
  }

  PRINTF("Final encoded bytes: ");
  HEX_PRINTF_INL((*cbor_result), cbor_bytes_len);
  return cbor_bytes_len;
}

//---------------------------------------------------------------------------------------------
// Encodes a map of 2 key-value pairs into CBOR. Keys are ints, values can be ints or strs.
int encode_2_pair_map_to_cbor(int key1, int int_value1, const char* str_value1,
                              int key2, int int_value2, const char* str_value2, unsigned char** cbor_result) {
  unsigned char* pairs[2] = {0};
  int pairs_lengths[2] = {0};

  PRINTF("Encoding map with 2 pairs.\n ");
  pairs_lengths[0] = encode_pair_to_cbor(key1, int_value1, 0, str_value1, strlen(str_value1), &pairs[0]);
  pairs_lengths[1] = encode_pair_to_cbor(key2, int_value2, 0, str_value2, strlen(str_value2), &pairs[1]);

  int cbor_bytes_len = encode_map_to_cbor(pairs, pairs_lengths, 2, cbor_result);

  free(pairs[0]);
  free(pairs[1]);

  return cbor_bytes_len;
}

//---------------------------------------------------------------------------------------------
// Encodes a map of 1 key-value pair into CBOR. Key is int, value is a byte string.
// NOTE: We assume all ints (keys or values) will be less than 24, to simplify encoding.
int encode_single_pair_map_to_cbor(int key, const unsigned char* byte_value, int byte_value_len, unsigned char** cbor_result) {
  unsigned char* pairs[1] = {0};
  int pairs_lengths[1] = {0};

  PRINTF("Encoding map with 1 pair.\n");
  pairs_lengths[0] = encode_pair_to_cbor(key, 0, byte_value, 0, byte_value_len, &pairs[0]);

  int cbor_bytes_len = encode_map_to_cbor(pairs, pairs_lengths, 1, cbor_result);

  free(pairs[0]);

  return cbor_bytes_len;
}

//---------------------------------------------------------------------------------------------
// Takes an int and encodes it into CBOR bytes, returning the length in bytes.
// Can be used for different things, since it receives the prefix as a parameter.
// NOTE: We are not supporting ints larger than 255 here.
static
int encode_num_to_cbor(int int_value, unsigned char** cbor_result, int prefix) {
  int encoded_len = 1;
  if(int_value >= CBOR_ONE_BYTE_LIMIT) {
    encoded_len += 1;
  }

  PRINTF("Encoded num will use %d bytes.\n", encoded_len);
  *cbor_result = (unsigned char*) malloc(encoded_len);

  int pos = 0;
  if(int_value < CBOR_ONE_BYTE_LIMIT) {
    PRINTF("Encoding num to 1 byte.\n");
    (*cbor_result)[pos++] = prefix | int_value;
  }
  else {
    PRINTF("Encoding num to 2 bytes.\n");
    (*cbor_result)[pos++] = prefix | CBOR_ONE_BYTE_LIMIT;
    (*cbor_result)[pos++] = int_value;
  }

  PRINTF("Encoded num: ");
  HEX_PRINTF_INL((*cbor_result), encoded_len);
  return encoded_len;
}

//---------------------------------------------------------------------------------------------
// Takes an int and encodes it into CBOR bytes, returning the length in bytes.
// Used explicitly for INT number CBOR encoding.
// NOTE: We are not supporting ints larger than 255 here.
int encode_int_to_cbor(int int_value, unsigned char** cbor_result) {
  PRINTF("Encoding int to CBOR.\n");
  return encode_num_to_cbor(int_value, cbor_result, CBOR_PREFIX_INT);
}

//---------------------------------------------------------------------------------------------
// Takes a byte string or text string and coverts it to CBOR bytes, returning the CBOR length in bytes.
// NOTE: We are not supporting byte strings longer than 255 chars here (though it would be simple to extend).
static
int encode_bytes_or_string_to_cbor(const unsigned char* input_array, int input_array_len, unsigned char** cbor_result, int prefix) {
  PRINTF("Encoding byte array of length %d, contents: ", input_array_len);
  HEX_PRINTF_INL(input_array, input_array_len);

  // Encode the header and gets the length.
  int header_len = encode_num_to_cbor(input_array_len, cbor_result, prefix);
  int encoded_len = header_len + input_array_len;
  PRINTF("Encoded bytes will use %d bytes.\n", encoded_len);

  // Add more bytes for the byte string, since the header is already in cbor_result.
  *cbor_result = (unsigned char*) realloc(*cbor_result, encoded_len);

  // Now copy the byte string to the result, after the header.
  memcpy((*cbor_result) + header_len, input_array, input_array_len);
  PRINTF("Encoded byte array: ");
  HEX_PRINTF_INL((*cbor_result), encoded_len);

  return encoded_len;
}

//---------------------------------------------------------------------------------------------
// Takes a byte string and coverts it to CBOR bytes, returning the CBOR length in bytes.
int encode_bytes_to_cbor(const unsigned char* input_array, int input_array_len, unsigned char** cbor_result) {
  return encode_bytes_or_string_to_cbor(input_array, input_array_len, cbor_result, CBOR_PREFIX_BYTES);
}

//---------------------------------------------------------------------------------------------
// Takes a text string and coverts it to CBOR bytes, returning the CBOR length in bytes.
int encode_string_to_cbor(const char* text_string, int text_string_len, unsigned char** cbor_result) {
  return encode_bytes_or_string_to_cbor((const unsigned char*) text_string, text_string_len, cbor_result, CBOR_PREFIX_TXT);
}
