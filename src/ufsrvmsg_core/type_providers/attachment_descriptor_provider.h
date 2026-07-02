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

//
// Created by devops on 9/19/21.
//

#ifndef UFSRV_ATTACHMENT_DESCRIPTOR_PROVIDER_H
#define UFSRV_ATTACHMENT_DESCRIPTOR_PROVIDER_H

#include <uflib/standard_c_includes.h>
#include <uflib/recycler/instance_type.h>
#include <attachments.h>

void InitAttachmentDescriptorRecyclerTypePool ();
unsigned AttachmentDescriptorPoolTypeNumber();
void AttachmentDescriptorIncrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples);
void AttachmentDescriptorDecrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples);
void AttachmentDescriptorReturnToRecycler (InstanceHolderForAttachmentDescriptor *, ContextData *ctx_data_ptr, unsigned long call_flags);
InstanceHolderForAttachmentDescriptor *AttachmentDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);

#endif //UFSRV_ATTACHMENT_DESCRIPTOR_PROVIDER_H
