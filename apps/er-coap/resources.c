
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

// TODO: fix this too.
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

  unsigned char* padded_id = left_pad_array(key_id, key_id_len, KEY_ID_LENGTH, 0);

  printf("Finding token for given identity: ");
  HEX_PRINTF(key_id, key_id_len);
  token_entry entry = {0};
  if(find_token_entry(padded_id, KEY_ID_LENGTH, &entry) == 0) {
    last_error = "Entry not found!";
    printf("%s\n", last_error);
    free_token_entry(&entry);
    free(padded_id);
    return 0;
  }
  free(padded_id);

  if(entry.cbor_len == 0) {
    last_error = "Entry has no token!";
    printf("%s\n", last_error);
    free_token_entry(&entry);
    return 0;
  }

  cwt* claims = parse_cbor_claims(entry.cbor, entry.cbor_len);
  if(claims == 0) {
    last_error = "Could not parse claims.";
    printf("%s\n", last_error);
    free_token_entry(&entry);
    return 0;
  }
  free_token_entry(&entry);

  char* error;
  if(validate_claims(claims, &error) == 0) {
    last_error = error;
    // TODO: note: since this will never be freed, any errors of this type will be memory leaks.
    printf("Problem validating claims: %s\n", error);
    return 0;
  }

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

  printf("Looking for scopes in list: %s, len %d\n", valid_scopes, strlen(valid_scopes));
  int scope_found = 0;
  char* scope_list = (char*) malloc(strlen(valid_scopes) + 1);
  strncpy(scope_list, valid_scopes, strlen(valid_scopes));
  printf("Copied list: %s, len %d\n", scope_list, strlen(scope_list));
  char* curr_scope = strtok(scope_list, ";");
  while(curr_scope) {
    // Check if this valid scope is the list of scopes in the token.
    printf("Checking next scope: %s, length %d\n", curr_scope, strlen(curr_scope));
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
int check_access_error(context_t* ctx, void* request, void* response) {
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