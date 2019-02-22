/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#ifndef RESOURCES_H
#define RESOURCES_H

#include "er-coap-dtls.h"

#define RS_ID "RS2"

// TODO: fix this, this is NOT extensible to add more resources.
#define SCOPES "HelloWorld;rw_Lock;r_Lock"

#define POS_GET 1
#define POS_POST 2
#define POS_PUT 3
#define POS_DEL 4

// Information about a scope: its name, and methods allowed by this scope.
typedef struct scope_info {
  char* name;
  unsigned char methods[4];
} scope_info;

// Information about a resource: its name, and the scope info (their name and methods allowed for each).
typedef struct resource_info {
  char* name;
  scope_info** scope_info_list;
  int scope_info_list_len;
} resource_info;

void register_resource_info(resource_info* resource);
int parse_and_check_access(struct dtls_context_t* ctx, void* request, void* response);

#endif // RESOURCES_H