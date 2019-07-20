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

#ifndef SRC_INCLUDE_ATTACHMENTS_H_
#define SRC_INCLUDE_ATTACHMENTS_H_

#include <instance_type.h>
#include <hashtable.h>
#include <instance_type.h>
#include <ufsrvresult_type.h>
#include <session_type.h>
#include <fence_type.h>
#include <attachment_descriptor_type.h>
#include <SignalService.pb-c.h>

typedef InstanceHolder InstanceHolderForAttachmentDescriptor;

inline static AttachmentDescriptor *
AttachmentDescriptorOffInstanceHolder(InstanceHolderForAttachmentDescriptor *instance_ptr) {
  return (AttachmentDescriptor *)GetInstance(instance_ptr);
}

void InitialiseAttachmentsHashTable (void);
void InitAttachmentDescriptorRecyclerTypePool ();
unsigned AttachmentDescriptorPoolTypeNumber();
void AttachmentDescriptorIncrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples);
void AttachmentDescriptorDecrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples);
void AttachmentDescriptorReturnToRecycler (InstanceHolderForAttachmentDescriptor *, ContextData *ctx_data_ptr, unsigned long call_flags);
InstanceHolderForAttachmentDescriptor *AttachmentDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);

//bool AttachmentDescriptorDelete (Session *sesn_ptr, AttachmentDescriptor *attch_ptr);
//UFSRVResult *AttachmentDescriptorValidateFromProto (Session *sesn_ptr, Fence *f_ptr, CollectionDescriptor *collection_attachments, size_t eid, bool flag_encode_key, CollectionDescriptor *collection_attachments_out);
//UFSRVResult *CheckAvatarForValidityFromProto (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, AttachmentDescriptor *attachment_descriptor_out);
bool AttachmentDescriptorDeleteById (Session *sesn_ptr, const char *);

//bool IsAttachmentDescriptionValid (Session *sesn_ptr, const char *nonce, const char *path);

//UFSRVResult *BackendAttachmentStoreLocationId (Session *sesn_ptr_target, const char *id, const char *location);
//UFSRVResult *BackendAttachmentGetFileLocation (Session *sesn_ptr, const char *id);
int DbAttachmentDelete (Session *sesn_ptr, const char *attachment_id);
//AttachmentDescriptor *AttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentRecord *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool);
//AttachmentDescriptor *TEMPAttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentPointer *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key);
UFSRVResult *DbAttachmentStore (Session *sesn_ptr,  AttachmentDescriptor *attachment_ptr, unsigned long fid, unsigned device_id);
void AttachmentDescriptorDestruct (AttachmentDescriptor *attachment_ptr, bool, bool self_destruct);
UFSRVResult *DbGetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attachment_ptr_in);
//AttachmentDescriptor *GetAttachmentDescriptorEphemeral (Session *sesn_ptr, const char *blob_id, AttachmentDescriptor *attch_ptr_in);
AttachmentDescriptor *GetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool);
//AttachmentDescriptor *AttachmentCacheGet (const char *id);
//bool AttachmentCachePut (const AttachmentDescriptor *attch_ptr);
//bool AttachmentCacheEvict (const AttachmentDescriptor *attch_ptr);
#endif /* SRC_INCLUDE_ATTACHMENTS_H_ */
