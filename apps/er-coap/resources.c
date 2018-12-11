/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rest-constants.h"
#include "rest-engine.h"
#include "dtls.h"

#include "resources.h"
#include "cwt.h"
#include "utils.h"
#include "key-token-store.h"
#include "dtls_helpers.h"

// TODO: improve this too.
// First position in array is GET, second is POST, third is PUT, fourth is DELETE.
static const char* res_hw_scopes[] = {"HelloWorld", 0, 0, 0};
static const char* res_lock_scopes[] = {"r_Lock;rw_Lock", 0, "rw_Lock", 0};

static char* last_error = 0;

// Checks if the token associated with the given key has access to the resource in the method being used.
int can_access_resource(const char* resource, int res_length, rest_resource_flags_t method, unsigned char* key_id, int key_id_len) {
  printf("Checking access to resource (%.*s), method (%d).\n", res_length, resource, method);

  if(memcmp(resource, "pair", res_length) == 0) {
    printf("Pairing resource is always accessible.\n");
    return 1;
  }

  printf("Finding token for given identity...\n");
  HEX_PRINTF(key_id, key_id_len);
  authz_entry entry = {0};
  if(find_authz_entry(key_id, key_id_len, &entry) == 0) {
    last_error = "Entry not found!";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    return 0;
  }

  printf("Entry found, checking if it has claims...\n");
  if(entry.claims_len == 0) {
    last_error = "Entry has no claims!";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    return 0;
  }

  printf("Parsing claims... \n");
  cwt* claims = parse_cbor_claims(entry.claims, entry.claims_len);
  claims->authz_info = entry;
  if(claims == 0) {
    last_error = "Could not parse claims.";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    return 0;
  }

  printf("Validating claims... \n");
  char* error;
  if(validate_claims(claims, &error) == 0) {
    last_error = error;
    // TODO: note: since this will never be freed, any errors of this type will be memory leaks.
    printf("Problem validating claims: %s\n", error);
    free_authz_entry(&entry);
    return 0;
  }
  free_authz_entry(&entry);

  // TODO: fix extensibility here too.
  // Now validate that the scope makes sense for the current resource.
  printf("Finding scopes for resource. Scopes in token: %s\n", claims->sco);
  const char** scope_map;
  if(memcmp(resource, "ace/helloWorld", res_length) == 0) {
    scope_map = res_hw_scopes;
  }
  else if(memcmp(resource, "ace/lock", res_length) == 0) {
    scope_map = res_lock_scopes;
  }
  else {
    last_error = "Unknown resource!";
    printf("%s\n", last_error);
    return 0;
  }

  printf("Resource found, checking method.\n");
  int pos = -1;
  switch(method){
    case METHOD_GET:
      pos = 0;
      break;
    case METHOD_POST:
      pos = 1;
      break;
    case METHOD_PUT:
      pos = 2;
      break;
    case METHOD_DELETE:
      pos = 3;
      break;
    default:
      last_error = "Unknown method!";
      printf("%s\n", last_error);
      return 0;
  }

  printf("Getting scope for method in pos %d.\n", pos);
  const char* valid_scopes = scope_map[pos];
  if(valid_scopes == 0) {
    last_error = "Token scopes do not give access to resource.";
    printf("For resource (%.*s), token scopes (%s) do not give access using this method (%d) - no scopes found.\n", res_length, resource, claims->sco, method);
    return 0;
  }

  printf("Looking for scopes in list: %s, len %u\n", valid_scopes, (unsigned int) strlen(valid_scopes));
  int scope_found = 0;
  char* scope_list = (char*) malloc(strlen(valid_scopes) + 1);
  memcpy(scope_list, valid_scopes, strlen(valid_scopes) + 1);
  printf("Copied list: %s, len %u\n", scope_list, (unsigned int) strlen(scope_list));
  char* curr_scope = strtok(scope_list, ";");
  while(curr_scope) {
    // Check if this valid scope is the list of scopes in the token.
    printf("Checking next scope: %s, length %u\n", curr_scope, (unsigned int) strlen(curr_scope));
    if(strstr(claims->sco, curr_scope) != 0) {
      scope_found = 1;
      break;
    }

    // Move to next scope.
    curr_scope = strtok(NULL, ";");
  }
  free(scope_list);

  if(scope_found == 0) {
    last_error = "Token scopes do not give access to resource.";
    printf("For resource (%.*s), token scopes (%s) do not give access using this method (%d).\n", res_length, resource, claims->sco, method);
    return 0;
  }

  // TODO: free everything in the cwt when it is no longer needed.

  printf("Can access resource according to check.\n");
  return 1;
}

// Call function to verify if client can access resource.
int check_access_error(struct dtls_context_t* ctx, void* request, void* response) {
  int access_error_found = 0;

  unsigned char* key_id = 0;
  int key_id_len = find_dtls_context_key_id(ctx, &key_id);
  if(key_id_len == 0) {
    char* error_msg = "Can't find DTLS handshake key id!";
    printf("%s\n", error_msg);
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    REST.set_response_payload(response, error_msg, strlen(error_msg));
    access_error_found = 1;
  }
  else {
    const char* resource = 0;
    int res_length = REST.get_url(request, &resource);
    printf("Got resource (%.*s) with length: %d\n", res_length, resource, res_length);
    rest_resource_flags_t method = REST.get_method_type(request);

    int can_access = can_access_resource(resource, res_length, method, key_id, key_id_len);
    if(!can_access) {
      printf("Can't access resource: %s\n", last_error);
      REST.set_response_status(response, REST.status.UNAUTHORIZED);
      REST.set_response_payload(response, last_error, strlen(last_error));
      access_error_found = 1;
    }
    else {
      printf("Can access resource!\n");
    }
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  return access_error_found;
}