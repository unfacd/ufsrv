/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifndef SRC_INCLUDE_USERS_PROTO_H_
#define SRC_INCLUDE_USERS_PROTO_H_

#include <utils.h>
#include <session_type.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <crypto_certificates.pb-c.h>
 #include <ufsrv_core/user/user_preference_descriptor_type.h>

#define PROTO_USER_RECORD_FULL 		0
#define PROTO_USER_RECORD_MINIMAL	1
#define PROTO_USER_RECORD_BYREF		1	//copy value by reference
#define PROTO_USER_RECORD_BYRDUP	0	//copy values by value (duplicate)

#define PROTO_USERCOMMAND(x)                ((x)->ufsrvcommand->usercommand)
#define PROTO_USERCOMMAND_ATTACHMENTS(x)    (PROTO_USERCOMMAND(x)->attachments)
#define PROTO_USERCOMMAND_HEADER(x)         (PROTO_USERCOMMAND(x)->header)
#define PROTO_USERCOMMAND_HEADER_ARGS(x)    (PROTO_USERCOMMAND_HEADER(x)->args)
#define PROTO_USERCOMMAND_HEADER_COMMAND(x) (PROTO_USERCOMMAND_HEADER(x)->command)

typedef struct SenderCertificateContext {
  ServerCertificate     *cert_server_ptr;
  SenderCertificate     *cert_sender_ptr;
  IdentityCertificate   *cert_identity_ptr;
  Certificate        *cert_key_ptr;
} SenderCertificateContext;

UserRecord *MakeUserRecordFromUsernameInProto (Session *sesn_ptr, const char *username, UserRecord *, bool flag_digest_mode);
UserRecord *MakeUserRecordFromSessionInProto (Session *sesn_ptr_source, UserRecord *, bool flag_digest_mode, bool);
UserRecord *MakeUserRecordFromUseridInProto (Session *sesn_ptr_carrier, unsigned long userid, UserRecord *user_record_supplied);
UserRecord *MakeUserRecordForSelfInProto (const Session *sesn_ptr, bool flag_digest_mode);
void MakeUfsrvUidInProto(UfsrvUid *uid_ptr, ProtobufCBinaryData *proto_ptr, bool flag_by_ref);

//UserRecord *MakeUserInfoInProto (Session *sesn_ptr, User *user_ptr_target);
void DestructUserInfoInProto (UserRecord *user_record_ptr, bool flag_self_destruct);
CollectionDescriptor *MakeSessionMessageUserPreferenceInProto (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr, CollectionDescriptor *collection_ptr_out);
CollectionDescriptor *LoadUserPreferenceBySessionMessageProto (MessageQueueMessage *mqm_ptr, CollectionDescriptor *collection_prefs_out);
const UserPreferenceDescriptor *MapShareListTypeToUserPref (UserCommand__ShareType share_type);
UFSRVResult *MakeSenderCertificate (Session *sesn_ptr, SenderCertificateContext *cert_ctx_ptr);
UFSRVResult *MakeIdentityCertificate (Session *sesn_ptr, IdentityCertificate *cert_identity_ptr, ServerCertificate *cert_server_ptr);

bool IsProtoUfsrvUidDefined (const ProtobufCBinaryData *ufsrvuid);

#endif /* SRC_INCLUDE_USERS_PROTO_H_ */
