/*
Modifications to enable ACE Constrained RS

Copyright 2018 Carnegie Mellon University. All Rights Reserved.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a BSD (SEI)-style license, please see https://github.com/cetic/6lbr/blob/develop/LICENSE or contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

DM18-1273
*/

#define CBOR_PREFIX_MAP 0xA0
#define CBOR_PRFIX_INT 0x00
#define CBOR_PREFIX_TXT 0x60
#define CBOR_PREFIX_EXTRA_INT8 0x18

#define CBOR_ONE_BYTE_LIMIT 24

#define CBOR_ERROR_CODE_KEY 15
#define CBOR_ERROR_DESC_KEY 16

#define CBOR_ERROR_CODE_INVALID_REQUEST 0

#define ENCODE_INT_TO_CBOR(int_value) CBOR_PRFIX_INT | int_value

int encode_map_to_cbor(int key1, int int_value1, const char* str_value1,
                       int key2, int int_value2, const char* str_value2, unsigned char** cbor_result);
int encode_string_to_cbor(const char* str_value, unsigned char** cbor_result);
int encode_int_to_cbor(int int_value, unsigned char** cbor_result);