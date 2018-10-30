
#ifndef RESOURCES_H
#define RESOURCES_H

#include "rest-constants.h"

#define RS_ID "RS2"

// TODO: fix this, this is NOT extensible to add more resources.
#define SCOPES "HelloWorld;rw_Lock;r_Lock"

int check_access_error(context_t* ctx, void* request, void* response);

#endif // RESOURCES_H