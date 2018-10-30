
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

#define HEX_PRINTF(byte_array, length) {                        \
        printf("Hex bytes: ");                                      \
        int i;                                                  \
        for (i=0; i < length; i++)                              \
          printf("%02x ", (unsigned int) (byte_array[i]));     \
        printf("\n");                                           \
     }

unsigned char* left_pad_array(const unsigned char* const byte_array, int array_length, int final_length, char padding);

#endif // UTILS_H
