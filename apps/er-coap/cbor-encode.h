
#define CBOR_ERROR_CODE_KEY 15
#define CBOR_ERROR_DESC_KEY 16

#define CBOR_ERROR_CODE_INVALID_REQUEST 0

int encode_map_to_cbor(int key1, int int_value1, char* str_value1,
                       int key2, int int_value2, char* str_value2, unsigned char* cbor_result);