/**
 * Copyright (C) 2015-2020 unfacd works
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UFSRV_UTILS_ZKGROUP_H
#define UFSRV_UTILS_ZKGROUP_H

#include "zkgroup_server_params_type.h"
#include "credential_response_type.h"
#include "group_credential_type.h"

#include <uuid_type.h>
#include <main_types.h>

typedef struct MessageSignedWithServerParams {
  ZKGroupServerParams *server_param;
  struct {
    uint8_t raw[SIGNATURE_LEN];
    uint8_t encoded[((SIGNATURE_LEN + 2) / 3) * 5];
  } notary_signature;
} MessageSignedWithServerParams;

ZKGroupServerParams *GenerateZKGroupServerParams(ZKGroupServerParams *server_params);



MessageSignedWithServerParams *SignUsingZKGroupServerParams(ZKGroupServerParams *server_params, uint8_t *message, size_t message_sz, MessageSignedWithServerParams *signed_message_in);
GroupCredential *IssueAuthCredentials(uint8_t *server_private_param, Uuid *uuid, int redemption_time, GroupCredential *group_credential_in);

#endif //UFSRV_UTILS_ZKGROUP_H
