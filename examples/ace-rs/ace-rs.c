/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

/**
 * \file
 *         Main ace-rs process and initialisation
 */


#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "rest-engine.h"
#include "dtls.h"

/*---------------------------------------------------------------------------*/

PROCESS(acers, "ACE RS");
AUTOSTART_PROCESSES(&acers);


/*---------------------------------------------------------------------------*/

PROCESS_THREAD(acers, ev, data)
{
  PROCESS_BEGIN();

  printf("Starting ACE RS (" CONTIKI_VERSION_STRING ")\n");

  // Initialize DTLS and both Erbium servers (CoAP and CoAPs).
  dtls_init();
  rest_init_engine();

  printf("CoAP servers started.\n");

  PROCESS_END();
}
