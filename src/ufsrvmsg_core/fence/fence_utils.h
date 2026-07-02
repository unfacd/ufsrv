/**
 * Copyright (C) 2015-2025 unfacd works
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

#ifndef SRC_INCLUDE_FENCE_UTILS_H_
#define SRC_INCLUDE_FENCE_UTILS_H_

#include <stdbool.h>
#include <hiredis.h>
#include <ufsrvmsg_core/fence/fence_identifier_type.h>
#include <uflib/adt/adt_hopscotch_hashtable.h>
#include <ufsrvmsg_core/fence/fence_enums_type.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <ufsrvresult_type.h>
#include <attachment_descriptor_type.h>
#include <digest_mode_enum.h>
#include <json/json.h>
#include <ufsrvmsg_core/SignalService.pb-c.h>

typedef UFSRVResult *(*CallbackExecutorForRedisResultSet)(PersistanceBackend *, redisReply *, ClientContextData *payload);

UFSRVResult *CheckFenceNameForValidity(Session *sesn_ptr, Fence *f_ptr, const char *fname_new);
UFSRVResult *CacheBackendUpdateFenceRegistry(Session *sesn_ptr, Fence *f_ptr, const char *, const char *cname_old_entry);
UFSRVResult *CacheBackendAddFenceRecord(Session *sesn_ptr, Fence *f_ptr, unsigned long fence_call_flags);

UFSRVResult *NetworkRemoveUserFromFence(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForFence *, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence);
UFSRVResult *NetworkRemoveUserFromInvitedFence(InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence);
UFSRVResult *ResetFencesForUser(InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType collection_type);
UFSRVResult *GetFencesNearByIndexRecords(Session *sesn_ptr_carrier, float longitude, float latitude, size_t radius, size_t count);


AttachmentDescriptor *AttachmentDescriptorGetFromProto(Session *sesn_ptr, AttachmentRecord *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key);
UFSRVResult *CheckAvatarForValidityFromProto(Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr);
AttachmentDescriptor *GetAttachmentDescriptorEphemeral(Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attch_ptr_in);

UFSRVResult *CacheBackendRemCacheRecordForFence(Session *sesn_ptr, Fence *f_ptr);

UFSRVResult *SearchMatchingFencesWithRawResultsPacked(Session *sesn_ptr_carrier, const char *search_text, size_t count, BufferDescriptor *buffer_ptr);

int DbBackendInsertFenceRecord(Fence *f_ptr, const char *jstr_fence);
UFSRVResult *DbBackendUpdateFenceKey(unsigned long fid, const unsigned char *fence_key);

UFSRVResult *FindFence(Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags);
bool IsFencePublic(const Fence *f_ptr);
FenceEvent *BackendUpdateFenceEvent(Session *sesn_ptr, FenceIdentifier *fs_ptr, FenceEvent *fe_ptr_in, unsigned event_type);

bool IsFenceIdFormatValid(const char *fid_str);

inline bool IsGroupAvatarPresent(DataMessage *data_msg_ptr)
{
	GroupContext 					*gctx_ptr							=	data_msg_ptr->group;

	if (IS_PRESENT(gctx_ptr->avatar))	return true;

	return false;
}

void FetchUsersList(Session *sesn_ptr, List *fences_list_ptr, HopscotchHashtableConfigurable *ht_ptr);
void
ProvideFenceOwnerUfsrvUid(unsigned long userid, void(^callback)(UfsrvUid *));

json_object *JsonFormatFenceDescriptor(Session *sesn_ptr, unsigned long fid, enum DigestMode digest_mode);

UFSRVResult *GenerateZKGroupParams(Fence *f_ptr);

UFSRVResult *TemporaryRedisFenceKeysBulkUpdate(PersistanceBackend *persistance_backend, CallbackExecutorForRedisResultSet result_set_executor, ClientContextData *ctx_data);
UFSRVResult *TemporaryRedisAddFenceKey(PersistanceBackend *persistance_backend, redisReply *redis_reply_provided, ClientContextData *cxt_data);

void TemporaryInitialiseBulkRedisFenceOps (void);

#endif /* SRC_INCLUDE_FENCE_UTILS_H_ */
