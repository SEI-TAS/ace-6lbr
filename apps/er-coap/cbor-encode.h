
#define CBOR_PREFIX_MAP 0xA0
#define CBOR_PRFIX_INT 0x00
#define CBOR_PREFIX_TXT 0x60
#define CBOR_PREFIX_EXTRA_INT8 0x18

#define CBOR_ONE_BYTE_LIMIT 24

#define CBOR_ERROR_CODE_KEY 15
#define CBOR_ERROR_DESC_KEY 16

#define CBOR_ERROR_CODE_INVALID_REQUEST 0

#define ENCODE_INT_TO_CBOR(int_value) CBOR_PRFIX_INT | int_value

int encode_map_to_cbor(int key1, int int_value1, const char* str_value1,
                       int key2, int int_value2, const char* str_value2, unsigned char** cbor_result);
int encode_string_to_cbor(const char* str_value, unsigned char** cbor_result);
int encode_int_to_cbor(int int_value, unsigned char** cbor_result);