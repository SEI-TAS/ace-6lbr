/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

Cn-cbor Copyright 2015 Carsten Bormann.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT-style license, please see https://github.com/cabo/cn-cbor/blob/master/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cn-cbor/cn-cbor.h"

cn_cbor* cn_cbor_mapget_int(const cn_cbor* cb, int key) {
  cn_cbor* cp;
  assert(cb);
  for (cp = cb->first_child; cp && cp->next; cp = cp->next->next) {
    switch(cp->type) {
    case CN_CBOR_UINT:
      if (cp->v.uint == (unsigned long)key) {
        return cp->next;
      }
    case CN_CBOR_INT:
      if (cp->v.sint == (long)key) {
        return cp->next;
      }
      break;
    default:
      ; // skip non-integer keys
    }
  }
  return NULL;
}

cn_cbor* cn_cbor_mapget_string(const cn_cbor* cb, const char* key) {
  cn_cbor *cp;
  int keylen;
  assert(cb);
  assert(key);
  keylen = strlen(key);
  for (cp = cb->first_child; cp && cp->next; cp = cp->next->next) {
    switch(cp->type) {
    case CN_CBOR_TEXT: // fall-through
    case CN_CBOR_BYTES:
      if (keylen != cp->length) {
        continue;
      }
      if (memcmp(key, cp->v.str, keylen) == 0) {
        return cp->next;
      }
    default:
      ; // skip non-string keys
    }
  }
  return NULL;
}

cn_cbor* cn_cbor_index(const cn_cbor* cb, unsigned int idx) {
  cn_cbor *cp;
  unsigned int i = 0;
  assert(cb);
  for (cp = cb->first_child; cp; cp = cp->next) {
    if (i == idx) {
      return cp;
    }
    i++;
  }
  return NULL;
}
