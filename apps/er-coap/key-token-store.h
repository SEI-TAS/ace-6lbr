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

#define MAX_AUTHZ_ENTRIES 20

typedef struct authz_entry {
  unsigned char* kid;
  unsigned char* key;
  int claims_len;
  unsigned char* claims;
  uint64_t time_received_seconds;
} authz_entry;

void initialize_key_token_store();
authz_entry* create_authz_entry(unsigned char* kid, int kid_len, unsigned char* key, int claims_len, unsigned char* claims, uint64_t time);
int store_authz_entry(authz_entry* entry);
int find_authz_entry(const unsigned char* const index, size_t idx_len, authz_entry *result);
void free_authz_entry(authz_entry* entry);
int remove_authz_entries(authz_entry* key_id_list[], int key_id_list_len);

typedef struct authz_entry_iterator {
  int entry_file_fd;
  int file_size;
  int curr_pos;
} authz_entry_iterator;

authz_entry_iterator authz_entry_iterator_initialize();
void authz_entry_iterator_finish(authz_entry_iterator iterator);
authz_entry* authz_entry_iterator_get_next(authz_entry_iterator* iterator);
void authz_entry_iterator_reopen(authz_entry_iterator* iterator);

#endif // KEY_TOKEN_STORE_H