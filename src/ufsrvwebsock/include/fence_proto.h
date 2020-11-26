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

#ifndef SRC_INCLUDE_FENCE_PROTO_H_
#define SRC_INCLUDE_FENCE_PROTO_H_

#include <ufsrv_core/fence/fence_type.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
#include <session_type.h>
#include <ufsrv_core/location/location_type.h>
#include <attachment_descriptor_type.h>
#include <ufsrv_core/SignalService.pb-c.h>//proto

#define PROTO_FENCECOMMAND(x) ((x)->ufsrvcommand->fencecommand)
#define PROTO_FENCECOMMAND_ATTACHMENTS(x)  (PROTO_FENCECOMMAND(x)->attachments)
#define PROTO_FENCECOMMAND_HEADER(x) ((PROTO_FENCECOMMAND(x))->header)
#define PROTO_FENCECOMMAND_HEADER_ARGS(x) ((PROTO_FENCECOMMAND_HEADER(x))->args)
#define PROTO_FENCECOMMAND_HEADER_COMMAND(x) ((PROTO_FENCECOMMAND_HEADER(x))->command)

//facilitates the return of constructed UserRecords from functions
typedef struct FenceUserRecordsDescription {
	size_t records_sz;
	UserRecord **user_records;
}FenceUserRecordsDescription;

BufferDescriptor *MakeFencesNearByInProtoPacked (Session *sesn_ptr, float longitude, float latitude, size_t, BufferDescriptor *);
void MakeFencePermissionsInProto(Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFencePermissionsUserListsInProto (Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFenceListSemanticsInProto (Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFencePrivacyModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFenceTypeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFenceDeliveryModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFenceJoinModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr);
void MakeFenceUserPreferencesInProto(Session *sesn_ptr, FenceStateDescriptor *fstate_ptr, FenceRecord *fence_record_ptr);

FenceRecord *MakeFenceRecordInProto (InstanceContextForSession *ctx_ptr, InstanceContextForFence *, FenceRecord *fence_record_ptr_in);
FenceRecord *MakeFenceRecordInProtoAsIdentifier (Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr_in);
FenceRecord *MakeFenceRecordInProtoAsIdentifierByParams (Session *sesn_ptr, unsigned long fid, FenceRecord *fence_record_ptr_in);
FenceUserRecordsDescription *MakeFenceMembersInProto (InstanceContextForSession *,  InstanceContextForFence *, unsigned long, unsigned long);
FenceUserRecordsDescription *MakeFenceInviteListFromNamesInProto (Session *sesn_ptr, char **members_invited, size_t members_sz, unsigned call_flags);
FenceUserRecordsDescription *MakeFenceInviteListInProto (Session *sesn_ptr, Fence *f_ptr, unsigned call_flags);
//FenceRecord **MakeFenceRecordsListFromFenceEventsInProto (Session *sesn_ptr, FenceEvent **fence_events, size_t fence_events_sz, unsigned long call_flags);
CollectionDescriptor *MakeFenceRecordsListFromFenceEventsInProto (Session *sesn_ptr, FenceEvent **fence_events, size_t fence_events_sz, unsigned long call_flags, CollectionDescriptor *collection_ptr_in);
//FenceRecord *MakeFenceRecordInProto (Session *sesn_ptr, Fence *f_ptr, unsigned call_flags);
LocationRecord *MakeUserLocationInProto (const User *user_ptr, bool flag_digest_mode);
LocationRecord *MakeFenceLocationInProto (const Fence *f_ptr, bool);
LocationRecord *MakeLocationDescriptionInProto (const LocationDescription *loc_ptr, bool flag_digest_mode,  bool dup_mode, LocationRecord *location_record_ptr_out);
void DestructFenceRecordsProto (FenceRecord **fence_records_ptr, unsigned count, bool self_destruct, bool self_destruct_record);
void DestructFenceRecordProto (FenceRecord *fence_record_ptr, bool flag_self_destruct);
void DestructUserRecords (UserRecord **user_records, size_t user_records_sz);
void DestructFenceUserRecordsDescription (FenceUserRecordsDescription  *desc_ptr, bool flag_self_destruct);
void DestructUserRecordsProto (UserRecord  **user_records_ptr, size_t members_sz, bool flag_self_destruct);
void DestructLocationRecordInProto (LocationRecord *location_record_ptr, bool);
void DestructFenceUserPreferencesInProto (FenceRecord *fence_record_ptr);

AttachmentRecord *TransferFenceAvatarAttachmentIfPresent (AttachmentPointer *, AttachmentRecord *record_ptr_in);
CollectionDescriptor *TEMPMakeAttachmentRecordFromAttachmentPointerInProto (AttachmentPointer *attachment_pointer_ptr, CollectionDescriptor *collection_attachment_records_out);
AttachmentDescriptor *TEMPAttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentPointer *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key);
CollectionDescriptor *MakeAttachmentRecordsInProto (CollectionDescriptor *collection_attachment_descriptors, CollectionDescriptor *, bool flag_dup);

AttachmentDescriptor *AttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentRecord *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool);

bool isFenceDeliveryModelEquals (const Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode);
void SetFenceDeliveryModeFromProto (uint64_t *setting, FenceRecord__DeliveryMode delivery_mode);

UFSRVResult *AttachmentDescriptorValidateFromProto (Session *sesn_ptr, Fence *f_ptr, CollectionDescriptor *collection_attachments, size_t eid, bool flag_encode_key, CollectionDescriptor *collection_attachments_out);

#endif /* SRC_INCLUDE_FENCE_PROTO_H_ */
