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

#ifndef SRC_INCLUDE_FENCE_UTILS_H_
#define SRC_INCLUDE_FENCE_UTILS_H_

#include <uflib/adt/adt_hopscotch_hashtable.h>
#include <session_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <ufsrvresult_type.h>
#include <attachment_descriptor_type.h>
#include <digest_mode_enum.h>
#include <json/json.h>
#include <ufsrv_core/SignalService.pb-c.h>

UFSRVResult *CheckFenceNameForValidity (Session *sesn_ptr, Fence *f_ptr, const char *fname_new);
UFSRVResult *CacheBackendUpdateFenceRegistry (Session *sesn_ptr, Fence *f_ptr, const char *, const char *cname_old_entry);
UFSRVResult *CacheBackendAddFenceRecord (Session *sesn_ptr, Fence *f_ptr, unsigned long fence_call_flags);

UFSRVResult *NetworkRemoveUserFromFence (InstanceHolderForSession *instance_sesn_ptr, InstanceContextForFence *, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence);
UFSRVResult *NetworkRemoveUserFromInvitedFence (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence);
UFSRVResult *ResetFencesForUser (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType collection_type);
UFSRVResult *GetFencesNearByIndexRecords (Session *sesn_ptr_carrier, float longitude, float latitude, size_t radius, size_t count);


AttachmentDescriptor *AttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentRecord *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key);
UFSRVResult *CheckAvatarForValidityFromProto (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr);
AttachmentDescriptor *GetAttachmentDescriptorEphemeral (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attch_ptr_in);

UFSRVResult *CacheBackendRemCacheRecordForFence (Session *sesn_ptr, Fence *f_ptr);

UFSRVResult *SearchMatchingFencesWithRawResultsPacked (Session *sesn_ptr_carrier, const char *search_text, size_t count, BufferDescriptor *buffer_ptr);

int DbBackendInsertFenceRecord (Session *sesn_ptr_carrier, unsigned long fid, const char *jstr_fence);

inline bool IsGroupAvatarPresent (DataMessage *data_msg_ptr)
{
	GroupContext 					*gctx_ptr							=	data_msg_ptr->group;

	if (IS_PRESENT(gctx_ptr->avatar))	return true;

	return false;
}

void FetchUsersList (Session *sesn_ptr, List *fences_list_ptr, HopscotchHashtableConfigurable *ht_ptr);

json_object *JsonFormatFenceDescriptor (Session *sesn_ptr, unsigned long fid, enum DigestMode digest_mode);

#endif /* SRC_INCLUDE_FENCE_UTILS_H_ */
