
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rest-constants.h"

#include "resources.h"
#include "cwt.h"
#include "utils.h"
#include "key-token-store.h"

// TODO: fix this too.
// First position in array is GET, second is POST, third is PUT, fourth is DELETE.
static const char* res_hw_scopes[] = {"HelloWorld", 0, 0, 0};
static const char* res_lock_scopes[] = {"r_Lock;rw_Lock", 0, "rw_Lock", 0};

int can_access_resource(const char* resource, rest_resource_flags_t method, unsigned char* key_id, int key_id_len) {
  unsigned char* padded_id = left_pad_array(key_id, key_id_len, KEY_ID_LENGTH, 0);

  token_entry entry;
  if(find_token_entry(padded_id, KEY_ID_LENGTH, &entry) == 0) {
    printf("Entry not found!");
    return 0;
  }

  if(entry.cbor_len == 0) {
    printf("Entry has no token!");
    return 0;
  }

  cwt* claims = parse_cbor_claims(entry.cbor, entry.cbor_len);
  if(claims == 0) {
    printf("Could not parse claims.");
    return 0;
  }

  char* error;
  if(validate_claims(claims, &error) == 0) {
    printf("Problem validating claims: %s", error);
    free(error);
    return 0;
  }

  // Now validate that the scope makes sense for the current resource.
  const char** scope_map;
  if(strcmp(resource, "ace/helloWorld")) {
    scope_map = res_hw_scopes;
  }
  else if(strcmp(resource, "ace/lock")) {
    scope_map = res_lock_scopes;
  }
  else {
    printf("Unknown resource!");
    return 0;
  }

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
      print("Unknown method!");
      return 0;
  }

  char* valid_scopes = scope_map[pos];
  if(valid_scopes == 0) {
    printf("Token scopes (%s) do not give access to this resource (%s) using this method (%s).", cwt->sco, resource, method);
    return 0;
  }

  int scope_found = 0;
  char* scope_list;
  strncpy(scope_list, valid_scopes, strlen(valid_scopes));
  char* curr_scope = strtok(scope_list, ";");
  while(curr_scope) {
    // Check if this valid scope is the list of scopes in the token.
    if(strstr(token->sco, curr_scope) != 0) {
      scope_found = 1;
      break
    }

    // Move to next scope.
    curr_scope = strtok(NULL, ";");
  }

  if(scope_found == 0) {
    printf("Token scopes (%s) do not give access to this resource (%s) using this method (%s).", cwt->sco, resource, method);
    return 0;
  }

  // TODO: free everything in the entry and the cwt when it is no longer needed.

  print("Can access resource!");
  return 1;
}