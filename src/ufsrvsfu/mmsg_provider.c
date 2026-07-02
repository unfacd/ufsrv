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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "mmsg_provider.h"
#include <uflib/main_types.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <uflib/recycler/instance_type.h>
#include <uflib/recycler/recycler_type.h>
#include <uflib/recycler/recycler.h>
#include <uflib/standard_valgrind_includes.h>
#include <syslog.h>

static RecyclerPoolHandle *MMsgTypePoolHandle;

static int TypePoolInitCallback_MMsg (ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback_Mmsg (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback_Mmsg (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback_Mmsg (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback_Mmsg (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps ops_mmsg = {
        TypePoolInitCallback_MMsg,
        TypePoolGetInitCallback_Mmsg,
        TypePoolPutInitCallback_Mmsg,
        TypePoolPrintCallback_Mmsg,
        TypePoolDestructCallback_Mmsg
};

/**
 * @brief Convinience function returning pre-casted reference to begining of the memory region allocated for use
 * in recvmmsg().
 * @return reference to memory region
 */
InstanceHolderForSfuMMsg *
GetMmsg() {
  InstanceHolderForSfuMMsg *instance_holder_ptr = RecyclerGet(SfuMmsgPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
  if (likely(IS_PRESENT(instance_holder_ptr))) {
    return  (instance_holder_ptr);
  }

  return NULL;
}

unsigned __attribute__((const))
SfuMmsgPoolTypeNumber()
{
  return MMsgTypePoolHandle->type;
}

/**
 * @brief The type pool is configured to return one monolithic memory block, which in turn is chunked up in unit sizes.
 * @return size of unit in bytes
 */
size_t __attribute__((const))
GetMmsgBaseVectorSize()
{
  return (sizeof(struct mmsghdr)          +
          sizeof(struct iovec)            +
          sizeof(struct sockaddr_in)      +
          CONFIG_MMSG_MAX_PACKET_SIZE_UDP +
          sizeof(struct mpsc_queue_node));
}

/**
 * 	@brief: "constructor" type intialiser for newly memory-instantiated objects just before attaching them to the recycler.
 * 	No InstanceHolder is available for object.
 * 	One off for the object's lifetime.
 *
 */
static int
TypePoolInitCallback_MMsg(ClientContextData *data_ptr, size_t oid)
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
  return GetMmsgBaseVectorSize() * _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ;
}

void
InitSfuMmsgRecyclerTypePool()
{
  size_t block_allocation_sz = _GetBlockAllocationSize();

#define _MEMSPECS_MMSG_ALLOCGROUPS 5 //max  allocation groups for this server instance
#define _MEMSPECS_MMSG_ALLOCGROUP_SZ	1 //number of mmsg per allocation group (1 because we are already allocating MAX_PACKETS per group)

  MMsgTypePoolHandle = RecyclerInitTypePool("MMsg", block_allocation_sz, _MEMSPECS_MMSG_ALLOCGROUPS, _MEMSPECS_MMSG_ALLOCGROUP_SZ, &ops_mmsg);

}

void
SfuMMsgReturnToRecycler(InstanceHolderForSfuMMsg *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
  RecyclerPut(SfuMmsgPoolTypeNumber(), instance_holder_ptr, (ContextData *)ctx_data_ptr, call_flags);
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
TypePoolGetInitCallback_Mmsg (InstanceHolder *instance_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  char *vector = (char *)GetInstance(instance_ptr);
  const struct mmsghdr 	    *mmsghdr = (struct mmsghdr *)vector;
  const struct iovec 		    *iovec = (struct iovec *)((char *)mmsghdr + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mmsghdr)));
  const struct sockaddr_in  *addr = (struct sockaddr_in  *)((char *)iovec + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct iovec)));
  const char *msg_pool = (char *)addr + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct sockaddr_in));
  const struct mpsc_queue_node *queue_node = (struct mpsc_queue_node *)((char *)msg_pool + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * CONFIG_MMSG_MAX_PACKET_SIZE_UDP));

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s: Mmsg mempool: mmsghdr:'%p', iovec:'%p', sockaddr:'%p', msgpool:'%p', mpsc_queue_node:'%p'", __func__, mmsghdr, iovec, addr, msg_pool, queue_node);
#endif

#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(mmsghdr, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(mmsghdr, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mmsghdr));

  VALGRIND_CREATE_MEMPOOL(iovec, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(iovec, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct iovec));

  VALGRIND_CREATE_MEMPOOL(addr, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(addr, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct sockaddr_in));

  VALGRIND_CREATE_MEMPOOL(msg_pool, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(msg_pool, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * CONFIG_MMSG_MAX_PACKET_SIZE_UDP);

  VALGRIND_CREATE_MEMPOOL(queue_node, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(queue_node, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mpsc_queue_node));
#endif

  for (size_t i = 0; i < _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ; ++i) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(mmsghdr, (char *)mmsghdr + (i * sizeof(struct mmsghdr)), sizeof(struct mmsghdr));
    VALGRIND_MEMPOOL_ALLOC(iovec, (char *)iovec + (i * sizeof(struct iovec)), sizeof(struct iovec));
    VALGRIND_MEMPOOL_ALLOC(addr, (char *)addr + (i * sizeof(struct sockaddr_in)), sizeof(struct sockaddr_in));
    VALGRIND_MEMPOOL_ALLOC(msg_pool, (char *)msg_pool + (i * CONFIG_MMSG_MAX_PACKET_SIZE_UDP), CONFIG_MMSG_MAX_PACKET_SIZE_UDP);
//    VALGRIND_MEMPOOL_ALLOC(queue_node, (char *)queue_node + (i * sizeof(mpsc_queue_node)), sizeof(mpsc_queue_node));
#endif

    struct mmsghdr 	    *mmsghdr_tracker = (struct mmsghdr *)((char *)mmsghdr + (i * sizeof(struct mmsghdr)));
    struct iovec 		    *iovec_tracker   = (struct iovec *)((char *)iovec + (i * sizeof(struct iovec)));
    struct sockaddr_in  *addr_tracker    = (struct sockaddr_in *)((char *)addr + (i * sizeof(struct sockaddr_in)));
    char *msg_tracker                    = (char *)msg_pool + (i * CONFIG_MMSG_MAX_PACKET_SIZE_UDP);

    iovec_tracker->iov_base = msg_tracker;
    iovec_tracker->iov_len  = CONFIG_MMSG_MAX_PACKET_SIZE_UDP - 1;//assuming text and allowing for terminating nul

    mmsghdr_tracker->msg_hdr.msg_iov 		      = iovec_tracker;
    mmsghdr_tracker->msg_hdr.msg_iovlen 	    = 1;
    mmsghdr_tracker->msg_hdr.msg_control      = 0;
    mmsghdr_tracker->msg_hdr.msg_controllen   = 0;

    mmsghdr_tracker->msg_hdr.msg_name         = addr_tracker;//Allocate room for retrieving peer's address
    mmsghdr_tracker->msg_hdr.msg_namelen      = sizeof(struct sockaddr_in);
  }

   return 0;
}

/**
 * @brief Return a reference to the allocation region belonging to the type 'struct mpsc_queue_node'. This a utility function,
 * mostly to pin-point the start of the allocation regions for queue_nodes within a pre-allocated type pool object.
 * @param vector The original type pool allocation chunk, where desired reference is mapped
 * @return pointer reference to start of region.
 */
struct mpsc_queue_node * __attribute__((pure))
GetQueueNodeReference(void *vector)
{
  size_t base_region_sz = (sizeof(struct mmsghdr) + sizeof(struct iovec) + sizeof(struct sockaddr_in) + CONFIG_MMSG_MAX_PACKET_SIZE_UDP);
  return (mpsc_queue_node *)(((char *)vector) + (base_region_sz * _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ));
}

void
SfuMMsgIncrementReference(InstanceHolderForSfuMMsg *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeReferenced(SfuMmsgPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
SfuMMsgDecrementReference(InstanceHolderForSfuMMsg *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeUnReferenced(SfuMmsgPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static int
TypePoolPutInitCallback_Mmsg (InstanceHolder *instance_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector = (char *)GetInstance(instance_ptr);
//  memset(vector, '\0', _GetBlockAllocationSize());

  struct mmsghdr 	    *mmsghdr = (struct mmsghdr *)vector;
  memset(mmsghdr, '\0', _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mmsghdr));

  struct iovec 		    *iovec = (struct iovec *)((char *)mmsghdr + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mmsghdr)));
  memset(iovec, '\0', _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct iovec));

  struct sockaddr_in  *addr = (struct sockaddr_in  *)((char *)iovec + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct iovec)));
  memset(addr, '\0', _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct sockaddr_in));

  char *msg_pool = (char *)addr + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct sockaddr_in));
  memset(msg_pool, '\0', _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * CONFIG_MMSG_MAX_PACKET_SIZE_UDP);

  struct mpsc_queue_node *queue_node = (struct mpsc_queue_node *)((char *)msg_pool + (_CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * CONFIG_MMSG_MAX_PACKET_SIZE_UDP));
  memset(queue_node, '\0', _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ * sizeof(struct mpsc_queue_node));

#if __VALGRIND_DRD
  VALGRIND_DESTROY_MEMPOOL(mmsghdr);
  VALGRIND_DESTROY_MEMPOOL(iovec);
  VALGRIND_DESTROY_MEMPOOL(addr);
  VALGRIND_DESTROY_MEMPOOL(msg_pool);
  VALGRIND_DESTROY_MEMPOOL(queue_node);
#endif

  return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback_Mmsg(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
//  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

/**
 * @brief:
 */
static int
TypePoolDestructCallback_Mmsg(InstanceHolder *instance_ptr, ContextData *context_data, unsigned long call_flags)
{
  char *vector =(char *)GetInstance(instance_ptr);

  return 0;

}