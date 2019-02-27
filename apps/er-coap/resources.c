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

// Hardcoded to 2 as we only have 2 for now. Can be increased, but avoiding that for now to reduce memory usage.
#define MAX_RESOURCES 2

// Limits the amount of scope names in the combined string.
#define MAX_SCOPES_STRING_LENGTH 40
#define SCOPE_SEPARATOR ';'

//---------------------------------------------------------------------------------------------
// Module to check if given requester has access to a given resource.
//---------------------------------------------------------------------------------------------

// All registered resources.
static resource_info* registered_resources[MAX_RESOURCES];
static int num_registered_resources = 0;

// A string storing all scopes in this RS.
static char combined_scopes[MAX_SCOPES_STRING_LENGTH] = {0};

// Store the latest error.
static char* last_error = 0;

//---------------------------------------------------------------------------------------------
// Adds a resource's information to the list of resources with scopes.
void register_resource_info(resource_info* resource) {
  registered_resources[num_registered_resources++] = resource;
}

//---------------------------------------------------------------------------------------------
// Checks if the token associated with the given key has access to the resource in the method being used.
// Returns 0 if resource can be accessed, or a REST error response code if applicable.
static
int can_access_resource(const char* resource, int res_length, rest_resource_flags_t method, unsigned char* key_id, int key_id_len) {
  printf("Checking access to resource (%.*s), method (%d).\n", res_length, resource, method);

  if(memcmp(resource, "pair", res_length) == 0) {
    printf("Pairing resource is always accessible.\n");
    return 0;
  }

  printf("Finding token for given identity...\n");
  HEX_PRINTF(key_id, key_id_len);
  authz_entry entry = {0};
  if(find_authz_entry(key_id, key_id_len, &entry) == 0) {
    last_error = "Token entry not found!";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    return REST.status.UNAUTHORIZED;
  }

  printf("Entry found, checking if it has claims...\n");
  if(entry.claims_len == 0) {
    last_error = "Entry has no claims!";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    return REST.status.UNAUTHORIZED;
  }

  printf("Parsing claims... \n");
  cwt* claims = parse_cbor_claims(entry.claims, entry.claims_len);
  claims->authz_info = &entry;
  if(claims == 0) {
    last_error = "Could not parse claims.";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    free_claims(claims);
    return REST.status.UNAUTHORIZED;
  }

  // Ok, we have an access token for this id/client!
  // Now validate that the scope makes sense for the current resource.
  // First find the scope/method data for the requested resource.
  printf("Finding scopes for resource. Scopes in token: %s\n", claims->sco);
  resource_info* curr_resource = 0;
  int i = 0;
  for(i = 0; i < num_registered_resources; i++)
  {
    if(memcmp(resource, registered_resources[i]->name, res_length) == 0) {
      curr_resource = registered_resources[i];
      break;
    }
  }
  if(curr_resource == 0) {
    last_error = "Unknown resource!";
    printf("%s\n", last_error);
    free_authz_entry(&entry);
    free_claims(claims);
    return REST.status.FORBIDDEN;
  }

  printf("Resource found, checking method...\n");
  int pos = -1;
  switch(method){
    case METHOD_GET:
      pos = POS_GET;
      break;
    case METHOD_POST:
      pos = POS_POST;
      break;
    case METHOD_PUT:
      pos = POS_PUT;
      break;
    case METHOD_DELETE:
      pos = POS_DEL;
      break;
    default:
      last_error = "Unknown method!";
      printf("%s\n", last_error);
      free_authz_entry(&entry);
      free_claims(claims);
      return REST.status.METHOD_NOT_ALLOWED;
  }

  printf("Resource and method are known, matching to scopes from token...\n");
  int some_scopes_in_claims_match_requested_resource = 0;
  int method_allowed = 0;
  for(i = 0; i < curr_resource->scope_info_list_len; i++) {
    scope_info* curr_scope = curr_resource->scope_info_list[i];
    if(strstr(claims->sco, curr_scope->name) != 0 ) {
      // At least one scope associated to this resource is validated by the token. We have to check method now.
      some_scopes_in_claims_match_requested_resource = 1;
      if(curr_scope->methods[pos] == 1) {
        printf("Scope %s allows access to this resource using method %d\n", curr_scope->name, method);
        method_allowed = 1;
        break;
      }
    }
  }

  if(some_scopes_in_claims_match_requested_resource == 0) {
    last_error = "No scopes in token are associated with this resource.";
    printf("No scopes in token are associated with requested resource (%.*s).\n", res_length, resource);
    free_authz_entry(&entry);
    free_claims(claims);
    return REST.status.FORBIDDEN;
  }

  if(method_allowed == 0) {
    last_error = "No scopes in token give access to this resource with the requested method.";
    printf("For resource (%.*s), there are no scopes that give access using this method (%d) (requested scope in token: (%s)).\n", res_length, resource, method, claims->sco);
    free_authz_entry(&entry);
    free_claims(claims);
    return REST.status.METHOD_NOT_ALLOWED;
  }

  printf("Validating expiration... \n");
  char* error;
  int error_code = validate_expiration(claims, &error);
  if(error_code) {
    last_error = error;
    // TODO: note: since this will never be freed, any errors of this type will be memory leaks.
    printf("Problem validating expiration: %s\n", error);
    free_authz_entry(&entry);
    free_claims(claims);
    return error_code;
  }

  free_authz_entry(&entry);
  free_claims(claims);
  printf("Can access resource according to check.\n");
  return 0;
}

//---------------------------------------------------------------------------------------------
// Call function to verify if client can access resource.
int parse_and_check_access(struct dtls_context_t* ctx, void* request, void* response) {
  int has_access = 0;

  unsigned char* key_id = 0;
  int key_id_len = find_dtls_context_key_id(ctx, &key_id);
  if(key_id_len == 0) {
    char* error_msg = "Can't find DTLS handshake key id!";
    printf("%s\n", error_msg);
    REST.set_response_status(response, REST.status.UNAUTHORIZED);
    REST.set_response_payload(response, error_msg, strlen(error_msg));
  }
  else {
    const char* resource = 0;
    int res_length = REST.get_url(request, &resource);
    printf("Got resource (%.*s) with length: %d\n", res_length, resource, res_length);
    rest_resource_flags_t method = REST.get_method_type(request);

    int error_code = can_access_resource(resource, res_length, method, key_id, key_id_len);
    if(error_code != 0) {
      printf("Can't access resource: %s\n", last_error);
      REST.set_response_status(response, error_code);
      REST.set_response_payload(response, last_error, strlen(last_error));
    }
    else {
      printf("Can access resource!\n");
      has_access = 1;
    }
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  return has_access;
}

//---------------------------------------------------------------------------------------------
// Creates a string will all this RS scopes.
void load_scopes_string() {
  // Loop for each resource.
  int i = 0;
  for(i = 0; i < num_registered_resources; i++) {
    // Loop for each scope in the resource.
    int j = 0;
    for(j = 0; j < registered_resources[i]->scope_info_list_len; j++) {
      strcat(combined_scopes, registered_resources[i]->scope_info_list[j]->name);
      strcat(combined_scopes, SCOPE_SEPARATOR);
    }
  }

  // Remove trailing separator.
  if(strlen(combined_scopes) > 0) {
    combined_scopes[strlen(combined_scopes) - 1] = 0;
  }

  return combined_scopes;
}

//---------------------------------------------------------------------------------------------
// Getter.
char* get_combined_scopes_string() {
  return combined_scopes;
}