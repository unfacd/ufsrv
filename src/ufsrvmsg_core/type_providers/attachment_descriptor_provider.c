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

#include <uflib/main_types.h>
#include <uflib/recycler/recycler.h>
#include <attachments.h>
#include <nportredird.h>
#include <log_message_literals.h>
#include "attachment_descriptor_provider.h"

extern ufsrv *const masterptr;

static RecyclerPoolHandle *AttachmentDescriptorPoolHandle;

static int	TypePoolInitCallback_AttachmentDescriptor (ClientContextData *data_ptr, size_t oid);
static int	TypePoolGetInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int	TypePoolPutInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char	*TypePoolPrintCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int	TypePoolDestructCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps ops_attachment_descriptor ={
        TypePoolInitCallback_AttachmentDescriptor,
        TypePoolGetInitCallback_AttachmentDescriptor,
        TypePoolPutInitCallback_AttachmentDescriptor,
        TypePoolPrintCallback_AttachmentDescriptor,
        TypePoolDestructCallback_AttachmentDescriptor
};

void InitAttachmentDescriptorRecyclerTypePool ()
{
	#define _THIS_EXPANSION_THRESHOLD (1024*100)
  //IMPORTANT: note 'sizeof(AttachmentDescriptor)+sizeof(uintptr_t)' as Attachment is Lru-managed which needs an extra offset
  AttachmentDescriptorPoolHandle = RecyclerInitTypePool("AttachmentDescriptor",
                                                        sizeof(AttachmentDescriptor) + sizeof(uintptr_t), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                                        _THIS_EXPANSION_THRESHOLD, &ops_attachment_descriptor);

  syslog(LOG_INFO, "%s: Initialised TypePool (WITH EXTRA uintptr_t offset for LRU): '%s'. TypeNumber:'%d', Block Size:'%lu'", __func__, AttachmentDescriptorPoolHandle->type_name, AttachmentDescriptorPoolHandle->type, AttachmentDescriptorPoolHandle->blocksz);
}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime. No InstanceHolder ref yet.
 *
 */
static int
TypePoolInitCallback_AttachmentDescriptor (ClientContextData *data_ptr, size_t oid)
{
  AttachmentDescriptor *descriptor_ptr = (AttachmentDescriptor *)data_ptr;

  return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Get().
 */
static int
TypePoolGetInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

  return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Put In this instance Fence *
 */
static int
TypePoolPutInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

  AttachmentDescriptorDestruct(descriptor_ptr, true, false);

  return 0;//success
}

static char *
TypePoolPrintCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

  return NULL;
}

static int
TypePoolDestructCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

  return 0;//success

}

void
AttachmentDescriptorIncrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeReferenced (AttachmentDescriptorPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
AttachmentDescriptorDecrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeUnReferenced (AttachmentDescriptorPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

unsigned
AttachmentDescriptorPoolTypeNumber()
{
  unsigned  type = AttachmentDescriptorPoolHandle->type;
  return type;
}

InstanceHolderForAttachmentDescriptor *
AttachmentDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags)
{
  InstanceHolder *instance_holder_ptr = RecyclerGet(AttachmentDescriptorPoolTypeNumber(), ctx_data_ptr, call_flags);
  if (unlikely(IS_EMPTY(instance_holder_ptr)))	goto return_error;

  return instance_holder_ptr;

  return_error:
  syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), (void *)0, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get AttachmentDescriptor instance");
  return NULL;

}

void
AttachmentDescriptorReturnToRecycler (InstanceHolderForAttachmentDescriptor *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
  RecyclerPut(AttachmentDescriptorPoolTypeNumber(), instance_holder_ptr, (ContextData *)ctx_data_ptr, call_flags);
}
