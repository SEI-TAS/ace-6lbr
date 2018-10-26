
#define RS_ID "RS2"

// TODO: fix this, this is NOT extensible to add more resources.
#define SCOPES "HelloWorld;rw_Lock;r_Lock"

// TODO: fix this too.
// First position in array is GET, second is POST, third is PUT, fourth is DELETE.
static const char* res_hw_scopes[] = {"HelloWorld", 0, 0, 0};
static const char* res_lock_scopes[] = {"r_Lock;rw_Lock", 0, "rw_Lock", 0};
