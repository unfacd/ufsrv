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

#ifndef UFSRV_USER_PROFILE_H
#define UFSRV_USER_PROFILE_H

#include <ufsrvuid_type.h>
#include <session_type.h>
#include <profile_key_store_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/user/user_profile_type.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <uuid_type.h>
#include <json/json.h>

ProfileKeyStore *DbBackendGetProfileKey(Session *sesn_ptr, const UfsrvUid *, enum ProfileKeyFormattingCode key_formatting_code, ProfileKeyStore *key_store_out);
UFSRVResult *DbBackendSetProfileKey (Session *sesn_ptr, const char *profile_key_encoded);
UFSRVResult *DbBackendSetProfileKeyIfNecessary (Session *sesn_ptr, const char *profile_key_encoded, bool is_force_update);
ProfileKeyStore *GetAccountAttributeForProfileKeyByStore (json_object *jobj_account, bool is_decoded, ProfileKeyStore *store_in);

UserProfileAuthDescriptor *UserProfileAuthDescriptorFromJson(json_object *jobj, UserProfileAuthDescriptor *profile_descriptor_in);
UFSRVResult *StoreUserProfileAuthDescriptor(unsigned long userid, const UserProfileAuthDescriptor *profile_descriptor);

Uuid *GetUuid(const char *username, Uuid *uuid_in, DbOpDescriptor *db_descriptor_in);
Uuid *GetUuidByUserId(unsigned long uid, Uuid *uuid_in, DbOpDescriptor *db_descriptor_in);

UserProfileAuthDescriptor *AllocateUserProfileAuthWithByRefAccess();
ProfileCredentialResponse *GetProfileKeyCredential(UfsrvUid *ufsrv_uid, ProfileCredentialRequest *profile_cred_request, char *profile_version, ProfileCredentialResponse *profile_cred_response_in);
ProfileCredentialRequest *DeserialiseProfileCredentialRequest(const char *cred_request_serialised, ProfileCredentialRequest *cred_request_in);

//convenient value getters callbacks
const uint8_t *UserProfileAuthDescriptorGetProfileKeySerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor);
const uint8_t *UserProfileAuthDescriptorGetProfileKeySerialised(const UserProfileAuthDescriptor *profile_descriptor);
const uint8_t *UserProfileAuthDescriptorGetCommitmentSerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor);
const uint8_t *UserProfileAuthDescriptorGetCommitmentSerialised(const UserProfileAuthDescriptor *profile_descriptor);
const uint8_t *UserProfileAuthDescriptorGetVersionSerialised(const UserProfileAuthDescriptor *profile_descriptor);
const uint8_t *UserProfileAuthDescriptorGetVersionSerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor);

#endif //UFSRV_USER_PROFILE_H
