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

#ifndef SRC_INCLUDE_ATTACHMENTS_H_
#define SRC_INCLUDE_ATTACHMENTS_H_

#include <uflib/recycler/instance_type.h>
#include <uflib/adt/adt_hashtable.h>
#include <uflib/recycler/instance_type.h>
#include <ufsrvresult_type.h>
#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <attachment_descriptor_type.h>
#include <ufsrvmsg_core/SignalService.pb-c.h>

typedef InstanceHolder InstanceHolderForAttachmentDescriptor;

inline static AttachmentDescriptor *
AttachmentDescriptorOffInstanceHolder(InstanceHolderForAttachmentDescriptor *instance_ptr) {
  return (AttachmentDescriptor *)GetInstance(instance_ptr);
}

void InitialiseAttachmentsHashTable (void);
int DbAttachmentDelete (Session *sesn_ptr, const char *attachment_id);
UFSRVResult *DbAttachmentStore (Session *sesn_ptr,  AttachmentDescriptor *attachment_ptr, unsigned long fid, unsigned device_id);
void AttachmentDescriptorDestruct (AttachmentDescriptor *attachment_ptr, bool deallocate_encoded, bool self_destruct);
UFSRVResult *DbGetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attachment_ptr_in);
AttachmentDescriptor *GetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool);
//AttachmentDescriptor *AttachmentCacheGet (const char *id);
//bool AttachmentCachePut (const AttachmentDescriptor *attch_ptr);
//bool AttachmentCacheEvict (const AttachmentDescriptor *attch_ptr);
#endif /* SRC_INCLUDE_ATTACHMENTS_H_ */
