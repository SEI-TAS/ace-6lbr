
#define RS_ID "RS2"

// TODO: fix this, this is NOT extensible to add more resources.
#define SCOPES "HelloWorld;rw_Lock;r_Lock"

void find_dtls_context_key_id();
int can_access_resource(const char* resource, rest_resource_flags_t method, unsigned char* key_id, int key_id_len) {