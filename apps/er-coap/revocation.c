/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "key-token-store.h"

// 0. Figure out how to store the IP of each AS associated with the token. When pairing?
// 1. Timed process or sleep.
// 2. CoAP client to send request.
// 3. Loop over all tokens.
// 4. Parse revocation response.
// 5. Remove revoked tokens froms storage.

void check_revoked_tokens() {

  authz_entry_iterator iterator = authz_entry_iterator_initialize();

  authz_entry* curr_entry = authz_entry_iterator_get_next(&authz_entry_iterator);
  while(curr_entry != 0) {

    curr_entry = authz_entry_iterator_get_next(&authz_entry_iterator);
  }

  authz_entry_iterator_finish(authz_entry_iterator);
}

