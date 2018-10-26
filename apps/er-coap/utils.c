#include <stdlib.h>
#include <string.h>

// Adds the given value as padding to the left of the array.
unsigned char* left_pad_array(const unsigned char* const byte_array, int array_length, int final_length, char padding) {
  unsigned char* padded_array = (unsigned char *) malloc(final_length);
  memset(padded_array, padding, final_length);
  int padding_len = final_length - array_length;
  memcpy(&padded_array[padding_len], byte_array, array_length);
  return padded_array;
}
