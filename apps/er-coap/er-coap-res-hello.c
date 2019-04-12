/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
/*
 * Endpoint called /pair for pairing an ACE RS with an AS
 * on 6lbr (Contiki)
 *
 * Dan Klinedinst, Software Engineering Institute, Carnegie Mellon University
*/


#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"

#include "resources.h"

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_hello, NULL, res_get_handler, NULL, NULL, NULL);

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  printf("Requesting Hello resource\n");
  const char* success_message = "HelloWorld!";
  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, success_message, strlen(success_message));
}

// Returns a structure with the information about scope and methods for this resource.
resource_info* get_resource_info_hello_world(char* resource_name) {
  scope_info* scope1 = (scope_info*) malloc(sizeof(scope_info));
  memset(scope1, 0, sizeof(scope_info));
  scope1->name = "HelloWorld";
  scope1->methods[POS_GET] = 1;

  resource_info* resource = (resource_info*) malloc(sizeof(resource_info));
  resource->name = resource_name;
  resource->scope_info_list_len = 1;
  resource->scope_info_list = (scope_info**) malloc(sizeof(scope_info*) * resource->scope_info_list_len);
  resource->scope_info_list[0] = scope1;

  return resource;
}