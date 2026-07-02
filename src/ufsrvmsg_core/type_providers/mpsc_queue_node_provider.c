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
#include "mpsc_queue_node_provider.h"
#include <uflib/adt/adt_mpsc_queue_type.h>
#include <uflib/recycler/recycler.h>
#include <string.h>

static RecyclerPoolHandle *MpscQueueNodeTypePoolHandle;

static int TypePoolInitCallback (ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps type_ops = {
        TypePoolInitCallback,
        TypePoolGetInitCallback,
        TypePoolPutInitCallback,
        TypePoolPrintCallback,
        TypePoolDestructCallback
};

unsigned __attribute__((const))
MpscQueueNodePoolTypeNumber()
{
  return MpscQueueNodeTypePoolHandle->type;
}

/**
 * @brief Convenience function to fethch a queue node from teh recycler.
 * @param is_reference_incremented if set, object will have its refcount incremented by one.
 * @return InstanceHolder for object
 */
InstanceHolderForMpscQueueNode *
GetMpscQueueNode(bool is_reference_incremented)
{
  InstanceHolderForMpscQueueNode *instance_holder_ptr = RecyclerGet(MpscQueueNodePoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
  if (likely(IS_PRESENT(instance_holder_ptr))) {
    if (is_reference_incremented) MpscQueueNodeIncrementReference(instance_holder_ptr, _ONCE_);
    return  (instance_holder_ptr);
  }

  return NULL;
}

/**
 * 	@brief: "constructor" type intialiser for newly memory-instantiated objects just before attaching them to the recycler.
 * 	No InstanceHolder is available for object.
 * 	One off for the object's lifetime.
 *
 */
static int
TypePoolInitCallback(ClientContextData *data_ptr, size_t oid)
{
  return 0;

}

/**
 * @brief Convenience function to provide the size of the monolithic memory block allocated by the type pool
 * @return
 */
inline static size_t
_GetBlockAllocationSize()
{
  return sizeof(struct mpsc_queue_node);
}

inline static const char *
_GetTypeName()
{
  return "MpscQueueNode";
}

void
InitMpscQueueNodeRecyclerTypePool()
{
  size_t block_allocation_sz = _GetBlockAllocationSize();

#define _MEMSPECS_ALLOCGROUPS         5 //max  allocation groups for this server instance
#define _MEMSPECS_ALLOCGROUP_BLOCK_SZ	64 //number of blocks per allocation group

  MpscQueueNodeTypePoolHandle = RecyclerInitTypePool(_GetTypeName(), block_allocation_sz, _MEMSPECS_ALLOCGROUPS, _MEMSPECS_ALLOCGROUP_BLOCK_SZ, &type_ops);

}

void
MpscQueueNodeReturnToRecycler(InstanceHolderForMpscQueueNode *instance_holder_ptr, ContextData *ctx_data_ptr, bool is_ref_decremented, unsigned long call_flags)
{
  if (is_ref_decremented) MpscQueueNodeDecrementReference(instance_holder_ptr, _ONCE_);
  RecyclerPut(MpscQueueNodePoolTypeNumber(), instance_holder_ptr, AS_CONTEXT_DATA(ctx_data_ptr), call_flags);
}

/**
 * @brief initialiser Each time the object is fetched from the recycler. On error, the data is automatically pushed back to the recycler.
 * and the original caller of RecyclerGet() gets NULL back.
 *
 * @param call_flags: passed down from the client through the lifecycle manager
 *
 */
static int
TypePoolGetInitCallback (InstanceHolder *instance_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  return 0;
}

void
MpscQueueNodeIncrementReference(InstanceHolderForMpscQueueNode *instance_descriptor_ptr, int multiples)
{
RecyclerTypeReferenced(MpscQueueNodePoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
MpscQueueNodeDecrementReference(InstanceHolderForMpscQueueNode *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeUnReferenced(MpscQueueNodePoolTypeNumber(), instance_descriptor_ptr, multiples);
}

/**
 * @brief: re-initialiser Each time the object is pushed back into the recycler.
 */
static int
TypePoolPutInitCallback(InstanceHolder *instance_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector =(char *)GetInstance(instance_ptr);
  memset(vector, '\0', _GetBlockAllocationSize());

  return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  //  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

/**
 * @brief:
 */
static int
TypePoolDestructCallback(InstanceHolder *instance_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector =(char *)GetInstance(instance_ptr);

  return 0;

}

