#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CBOR_PREFIX_MAP 0xA0
#define CBOR_PRFIX_INT 0x00
#define CBOR_PREFIX_TXT 0x60
#define CBOR_PREFIX_EXTRA_INT8 0x18

#define CBOR_ONE_BYTE_LIMIT 24

int encode_pair_to_cbor(int key, int int_value, const char* str_value, unsigned char* cbor_result);

// Encodes a map of 2 key-value pairs into CBOR. Keys are ints, values can be ints or strs.
int encode_map_to_cbor(int key1, int int_value1, const char* str_value1,
                       int key2, int int_value2, const char* str_value2, unsigned char* cbor_result) {
  // Map will have 2 pairs.
  unsigned char cbor_map_header = CBOR_PREFIX_MAP & 2;
  unsigned char* pair1_cbor = 0;
  int pair1_len = encode_pair_to_cbor(key1, int_value1, str_value1, pair1_cbor);
  unsigned char* pair2_cbor = 0;
  int pair2_len = encode_pair_to_cbor(key2, int_value2, str_value2, pair2_cbor);

  // Move both encoded bytes into a unified buffer.
  int cbor_bytes_len = 1 + pair1_len + pair2_len;
  printf("Encoding both pairs in map, total length %d.\n", cbor_bytes_len);
  unsigned char* cbor_bytes = (unsigned char*) malloc(cbor_bytes_len);
  cbor_bytes[0] = cbor_map_header;
  memcpy(cbor_bytes + 1, pair1_cbor, pair1_len);
  memcpy(cbor_bytes + 1 + pair1_len, pair2_cbor, pair2_len);
  printf("Finished encoding map, cleaning up.\n");
  free(pair1_cbor);
  free(pair2_cbor);

  return cbor_bytes_len;
}

// NOTE: We assume all ints, keys or values, will be less than 24, to simplify encoding.
int encode_pair_to_cbor(int key, int int_value, const char* str_value, unsigned char* cbor_result) {
  printf("Encoding pair to CBOR, with key %d, int value %d.\n", key, int_value);

  // Calculate the length of the encoded result. An int key less than 24 fits in 1 B.
  // The type for an int (plus its value) or a text string will need at least 1 more.
  int encoded_len = 2;

  // Text strings will need more if they have more than 23 chars.
  if(str_value != 0) {
    int str_value_len = strlen(str_value);
    if(str_value_len >= CBOR_ONE_BYTE_LIMIT) {
      // We assume text strings wont be longer than 255 chars.
      encoded_len += 1;
    }
    encoded_len += str_value_len;
  }

  printf("Encoded pair will use %d bytes.\n", encoded_len);
  cbor_result = (unsigned char*) malloc(encoded_len);

  // Encode using the CBOR RFC rules. Using & adds the type prefix.
  int pos = 0;
  cbor_result[pos++] = CBOR_PRFIX_INT & key;
  if(str_value != 0) {
    int str_value_len = strlen(str_value);
    printf("Encoding string %s of length %d.\n", str_value, str_value_len);
    if(str_value_len < CBOR_ONE_BYTE_LIMIT) {
      printf("Adding 1 byte txt header.\n");
      cbor_result[pos++] = CBOR_PREFIX_TXT & str_value_len;
    }
    else {
      printf("Adding 2 byte txt header.\n");
      cbor_result[pos++] = CBOR_PREFIX_TXT & CBOR_ONE_BYTE_LIMIT;
      cbor_result[pos++] = str_value_len;
    }

    // Now actually add the string.
    memcpy(cbor_result + pos, str_value, str_value_len);
    printf("String encoded.\n");
  }
  else {
    cbor_result[pos++] = CBOR_PRFIX_INT & int_value;
    printf("Int encoded.\n");
  }

  return encoded_len;
}