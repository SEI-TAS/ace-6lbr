/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#ifndef KEY_TOKEN_STORE_H
#define KEY_TOKEN_STORE_H

#include <stdlib.h>

typedef struct authz_entry {
  unsigned char* kid;
  unsigned char* key;
  int claims_len;
  unsigned char* claims;
  uint64_t time_received_seconds;
} authz_entry;

void initialize_key_token_store();
int store_authz_entry(authz_entry* entry);
int find_authz_entry(const unsigned char* const index, size_t idx_len, authz_entry *result);
void free_authz_entry(authz_entry* entry);

#endif // KEY_TOKEN_STORE_H