
#ifndef RESOURCES_H
#define RESOURCES_H

#include "rest-constants.h"

#define RS_ID "RS2"

// TODO: fix this, this is NOT extensible to add more resources.
#define SCOPES "HelloWorld;rw_Lock;r_Lock"

int can_access_resource(const char* resource, int res_length, rest_resource_flags_t method, unsigned char* key_id, int key_id_len);

#endif // RESOURCES_H