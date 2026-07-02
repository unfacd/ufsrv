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

#include <coroutine_run_context_provider.h>
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <uflib/main_types.h>
#include <uflib/recycler/instance_type.h>
#include <uflib/recycler/recycler_type.h>
#include <uflib/recycler/recycler.h>
#include <uflib/standard_valgrind_includes.h>

static RecyclerPoolHandle *CoroutineRunContextTypePoolHandle;

inline static size_t _GetBlockAllocationSize();
static int TypePoolInitCallback_CoroutineRunContext(ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback_CoroutineRunContext(InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback_CoroutineRunContext(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback_CoroutineRunContext(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback_CoroutineRunContext(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps ops_coroutine_context = {
        TypePoolInitCallback_CoroutineRunContext ,
        TypePoolGetInitCallback_CoroutineRunContext ,
        TypePoolPutInitCallback_CoroutineRunContext ,
        TypePoolPrintCallback_CoroutineRunContext ,
        TypePoolDestructCallback_CoroutineRunContext
};

unsigned __attribute__((const))
CoroutineRunContextPoolTypeNumber()
{
  return CoroutineRunContextTypePoolHandle->type;
}

/**
 * @brief Convenience function for instantiating types.
 * @return
 */
InstanceHolderForCoroutineContext *
GetCoroutineRunContext(bool is_ref_counted) {
  InstanceHolderForCoroutineContext *instance_holder_ptr = RecyclerGet(CoroutineRunContextPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
  if (likely(IS_PRESENT(instance_holder_ptr))) {
    if (is_ref_counted) CoroutineRunContextIncrementReference(instance_holder_ptr, _ONCE_);
    return  (instance_holder_ptr);
  }

  return NULL;
}

/**
 * @brief Main initiliser for pool type. Must be called once before instantiating instances.
 */
void
InitCoroutineRunContextRecyclerTypePool()
{
  size_t block_allocation_sz = _GetBlockAllocationSize();

#define _MEMSPECS_MMSG_ALLOCGROUPS 2 //max  allocation groups for this server instance
#define _MEMSPECS_MMSG_ALLOCGROUP_SZ	1024 //number of mmsg per allocation group (1 because we are already allocating MAX_PACKETS per group)

  CoroutineRunContextTypePoolHandle = RecyclerInitTypePool("CoroutineContext", block_allocation_sz, _MEMSPECS_MMSG_ALLOCGROUPS, _MEMSPECS_MMSG_ALLOCGROUP_SZ, &ops_coroutine_context);

}

void
CoroutineRunContextReturnToRecycler(InstanceHolderForCoroutineContext *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
  RecyclerPut(CoroutineRunContextPoolTypeNumber(), instance_holder_ptr, (ContextData *)ctx_data_ptr, call_flags);
}

void
CoroutineRunContextIncrementReference(InstanceHolderForCoroutineContext *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeReferenced(CoroutineRunContextPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
CoroutineRunContextDecrementReference(InstanceHolderForCoroutineContext *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeUnReferenced(CoroutineRunContextPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

/**
 * 	@brief "constructor" type intialiser for newly memory-instantiated objects just before attaching them to the recycler.
 * 	No InstanceHolder is available for object.
 * 	One off for the object's lifetime.
 *
 */
static int
TypePoolInitCallback_CoroutineRunContext(ClientContextData *data_ptr, size_t oid)
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
  return sizeof(CoroutineRunContext);
}

/**
 * @brief initialiser Each time the object is fetched from the recycler. On error, the data is automatically pushed back to the recycler.
 * and the original caller of RecyclerGet() gets NULL back.
 *
 * @param call_flags: passed down from the client through the lifecycle manager
 *
 * |-------|------|-------------|--------------------------|----------------|
 * mmsghdr | iovc | sockaddr_in | MMSG_MAX_PACKET_SIZE_UDP | mpsc_queue_node
 */
static int
TypePoolGetInitCallback_CoroutineRunContext (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{

  return 0;
}

/**
 * @brief initialiser Each time the object is pushed back into the recycler.
 */
static int
TypePoolPutInitCallback_CoroutineRunContext(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector =(char *)GetInstance(data_ptr);
  memset(vector, '\0', _GetBlockAllocationSize());

  return 0;//success

}

/**
 * @brief initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback_CoroutineRunContext (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  //  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

/**
 * @brief
 */
static int
TypePoolDestructCallback_CoroutineRunContext (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector =(char *)GetInstance(data_ptr);

  return 0;

}