/**
 * Copyright (C) 2015-2021 unfacd works
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

#include <signal_ffi.h>
#include "credential_response_type.h"
#include "authentication_credential_type.h"
#include "zkgroup_params_type.h"

#include <uflib/uuid_type.h>
#include <uflib/main_types.h>
#include "zkgroup_masterkey_type.h"
#include "zkgroup_server_params_type.h"

#define SIGNATURE_SIZE SignalSIGNATURE_LEN //64
#define RANDOMNESS_SIZE SignalRANDOMNESS_LEN //32
#define UUID_SIZE       SignalUUID_LEN //16
#define AUTH_CREDENTIAL_RESPONSE_SIZE  SignalAUTH_CREDENTIAL_RESPONSE_LEN //361

typedef struct MessageSignedWithServerParams {
  ZKGroupServerParams *server_param;
  struct {
    uint8_t raw[SIGNATURE_SIZE];
    uint8_t encoded[((SIGNATURE_SIZE + 2) / 3) * 5];
  } notary_signature;
} MessageSignedWithServerParams;

ZKGroupServerParams *GenerateZKGroupServerParams(ZKGroupServerParams *server_params);

MessageSignedWithServerParams *SignUsingZKGroupServerParams(ZKGroupServerParams *server_params, uint8_t *message, size_t message_sz, MessageSignedWithServerParams *signed_message_in);
AuthenticationCredential *IssueAuthCredentials(const uint8_t *server_private_param, const Uuid *uuid, int redemption_time, AuthenticationCredential *group_credential_in);

ZKGroupParams *GenerateZKGroupSecretParams (ZKGroupParams *zkgroup_params_in);
ZKGroupParams *DeriveZKGroupSecretParamsFromMasterKey (ZKGroupMasterKey *zkgroup_masterkey, ZKGroupParams *zkgroup_params_in);
ZKGroupParams *ZKGroupGetPublicParams (ZKGroupParams *zkgroup_params);
ZKGroupParams *ZKGroupGetGroupIdentifier(ZKGroupParams *zkgroup_params);
ZKGroupMasterKey *GetMasterKey (ZKGroupParams *zkgroup_params, ZKGroupMasterKey *zkgroup_masterkey_in);

#endif //UFSRV_UTILS_ZKGROUP_H
