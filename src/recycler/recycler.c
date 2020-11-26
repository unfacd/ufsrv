/**
 * Copyright (C) 2015-2020 unfacd works
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

#include <standard_c_includes.h>
#include <pthread.h>
#include <recycler/recycler.h>
#include <recycler/instances_list.h>
#include <uflib/adt/adt_queue.h>
#include <recycler/instance_type.h>
#include <recycler/recycler_log_strings.h>

//http://valgrind.org/docs/manual/mc-manual.html#mc-manual.mempools
#define __VALGRIND_DRD 1

#if __VALGRIND_DRD
# include <valgrind/valgrind.h>
# include <valgrind/drd.h>
# include <valgrind_drd_inlines.h>
#	include <valgrind/memcheck.h>
#endif


//when we allocate types we allocate by factor of that many at once
#define _RECYCLER_INIT_TYPE_COUNT 10

// each individual object (of a given type) is prefixed with this pool management header
typedef struct RecyclerPoolTypeEnvelop {
	atomic_size_t _refcount;
//	RecyclerClientData *client_data;
	size_t oid;//sequential value used as object id which is fixed for the lifetime of the type. unique across Type
	InstancesList instances_list;
} RecyclerPoolTypeEnvelop;

#ifdef __ATOMIC_SPINLOCK
	//https://nahratzah.wordpress.com/2012/10/12/a-trivial-fair-spinlock/
	typedef struct atomic_spinlock_t {
	    /*atomic_uint*/ _Atomic bool active;//initialise to 1
	    /*atomic_uint*/ _Atomic unsigned int avail;//initialise to 0
	} atomic_spinlock_t;

#if (defined(__GNUC__) || defined(__clang__)) &&			\
    (defined(__amd64__) || defined(__x86_64__) ||			\
     defined(__i386__) || defined(__ia64__))
#define SPINWAIT() do { __asm __volatile("pause":::"memory"); } while (0)
#else
#define SPINWAIT()  do { /* nothing */ } while (0)
#endif

#endif

//the actual memory pool (aka Recycler Pool), along with relevant meta data. This pool is of fixed size, multiple pools can be allocated
//seperate groups for any given type under teh management of the pool. A management structure, RecyclerPoolDefinition, is responsible for tracking
//groups and defining common attributes per type; eg, type ops.
typedef struct TypePoolAllocationGroup {
	unsigned groupid;//set to the rid of its first object, to signify boundary
	size_t pool_size; //overall size, mostly derived from parent pool
	size_t head, tail; //as applied against pool_queue
	size_t leased_size; //how many memory slots are currently occupied by clients
	void *pool_memory;	//the actual memory chunk, delineated at the boundaries of RecyclerPoolTypeEnvelop+blockszfor pool_size
	RecyclerPoolTypeEnvelop **pool_queue;	//classic circular array queue to track which memory chunks are leased out

#ifdef __ATOMIC_SPINLOCK
	atomic_spinlock_t atomic_spin_lock;
#else
	pthread_spinlock_t spin_lock;//protects ref-counting and queue manipulation
#endif
} TypePoolAllocationGroup;

typedef struct RecyclerPoolDefinition {
	RecyclerPoolHandle pool_handle; //high-level identifying meta data per Type

#ifdef __ATOMIC_SPINLOCK
	atomic_spinlock_t atomic_spin_lock;
#else
	pthread_spinlock_t spin_lock;//shouldn't be highly contested. Only needed when expansion is performed
#endif
	unsigned expasnion_threshold;//ration of leased_size/pool_size that triggers pool expansion

	RecyclerPoolOps ops;//fixed lifecycle callbacks set per type

	void **pool_memory2;//over-arching indexer of individual allocation groups. indexed/allocated in unison with groups

	int alocated_groups_sz;//how many groups currently allocated
	size_t current_max_capacity;//how much can we store based on current allocated_groups_sz*expasnion_threshold
	size_t group_allocation_sz; //fixed number, defining the size of teh group and used for growing the size by that factor

	TypePoolAllocationGroup **allocation_groups;//memory allocation groups Fixed array.

}	RecyclerPoolDefinition;

typedef struct Recycler {
	RecyclerPoolDefinition **recyclers;
	unsigned count_typeslots; //initially recycler is initialised with that amount of slots, but not all slots are defined
	unsigned count_types;//currently defined types
} Recycler;

#define RECYCLER_POOL_MEMORY_GROUP(x, y)	(x->pool_memory[y])
#define RECYCLER_POOL_MEMORY_GROUPS_SZ(x)	(x->alocated_groups_sz)
#define RECYCLER_POOL_ALLOCATED_GROUPS_SZ(x)	(x->alocated_groups_sz)
#define RECYCLER_POOL_CURRENT_MAX_CAPACITY(x)	(x->current_max_capacity)
#define RECYCLER_POOL_CHUNK_SZ(x)	(x->expasnion_threshold)
#define RECYCLER_POOL_ALLOCATION_GROUP(x, y)	(x->allocation_groups[y])
#define RECYCLER_POOL_LOCK(x)	(x->spin_lock)
#define RECYCLER_POOL_LOCK_PTR(x)	&(x->spin_lock)
#define RECYCLER_POOL_HANDLE(x)	(x->pool_handle)
#define RECYCLER_POOL_HANDLE_PTR(x)	&(x->pool_handle)
#define RECYCLER_POOL_TYPENAME(x)	(x->pool_handle.type_name)

//expects pointer to AllocationGroup
#define ALLOCGROUP_GROUPID(x)	x->groupid
#define ALLOCGROUP_POOLSIZE(x)	x->pool_size
#define ALLOCGROUP_HEAD(x)	x->head
#define ALLOCGROUP_TAIL(x)	x->tail
#define ALLOCGROUP_LEASEDSIZE(x)	x->leased_size
#define ALLOCGROUP_SPINLOCK(x)	x->spin_lock
#define ALLOCGROUP_SPINLOCK_PTR(x)	&(x->spin_lock)
#define ALLOCGROUP_POOLMEMORY(x)	x->pool_memory
#define ALLOCGROUP_POOLQUEUE(x)	x->pool_queue

#define RECYCLER_TYPE_INIT_CALLBACK(x) x->ops.poolop_init_callback
#define RECYCLER_TYPE_INIT_CALLBACK_INVOKE(x, ...) (x->ops.poolop_init_callback)(__VA_ARGS__)
#define RECYCLER_TYPE_INITGET_CALLBACK(x) x->ops.poolop_initget_callback
#define RECYCLER_TYPE_INITGET_CALLBACK_INVOKE(x, ...) (x->ops.poolop_initget_callback)(__VA_ARGS__)
#define RECYCLER_TYPE_INITPUT_CALLBACK(x) x->ops.poolop_initput_callback
#define RECYCLER_TYPE_INITPUT_CALLBACK_INVOKE(x, ...) (x->ops.poolop_initput_callback)(__VA_ARGS__)

static Recycler recycler = {NULL, 0, 0};
static Recycler *const recycler_ptr = &recycler;

static inline void _EnQueue (RecyclerPoolHandle *, TypePoolAllocationGroup *alloc_group_ptr, RecyclerPoolTypeEnvelop *);
static inline  RecyclerPoolTypeEnvelop *_DeQueue (RecyclerPoolHandle *, TypePoolAllocationGroup *alloc_group_ptr);
static inline  void _PrintQueueEntry (RecyclerPoolDefinition *pool_ptr, TypePoolAllocationGroup *, RecyclerPoolTypeEnvelop *env_ptr);
static RecyclerPoolHandle *_TypePoolExpandAllocationGroup(RecyclerPoolDefinition *pool_ptr, size_t group_allocation_sz);
static inline TypePoolAllocationGroup *_TypePoolAllocationGroupGet (RecyclerPoolDefinition *pool_ptr, RecyclerPoolTypeEnvelop *env_ptr);
inline static RecyclerPoolTypeEnvelop *DeriveHeaderEnvelopeFromInstanceHolder (InstanceHolder *);

static bool IsRecyclerTypeQueueEmpty (unsigned type, TypePoolAllocationGroup *alloc_group_ptr) __attribute__((unused));
static bool IsRecyclerTypeQueueFull (unsigned type, TypePoolAllocationGroup *alloc_group_ptr) __attribute__((unused));

/**
 * 	@brief:	Called once per Type to setup the the memory pool arrangements  for objects of the given type.
 * 	@returns:  pointer to a pre-allocated area, which is fixed for the type, containing meta data. No need to free at client side
 */
RecyclerPoolHandle *
RecyclerInitTypePool(const char *typename, size_t blocksz, size_t group_allocation_sz, size_t expansion_threshold, RecyclerPoolOps *pool_ops_ptr)
{
	RecyclerPoolDefinition *pool_ptr = NULL;

	__expansion_block:

	//signifies at type-capacity condition. Also, bootstraps the rcycler first time it's called to create a type (0 == 0) condition
	if (recycler_ptr->count_typeslots == recycler_ptr->count_types) {
		RecyclerPoolDefinition **expanded_recylers = NULL;

		//expand recycler types slots by a factor of _RECYECLER_INIT_TYPE_COUNT
		expanded_recylers = realloc(recycler_ptr->recyclers, (recycler_ptr->count_typeslots + _RECYCLER_INIT_TYPE_COUNT) * sizeof(RecyclerPoolDefinition *));

		if (expanded_recylers) {
			recycler_ptr->recyclers = expanded_recylers;
			recycler_ptr->count_typeslots += _RECYCLER_INIT_TYPE_COUNT;
			recycler_ptr->count_types++;

			//allocate space for new type
			recycler_ptr->recyclers[recycler_ptr->count_types - 1] = calloc(1, sizeof(RecyclerPoolDefinition));

			pool_ptr = recycler_ptr->recyclers[recycler_ptr->count_types - 1];

			pool_ptr->pool_handle.type = recycler_ptr->count_types;

#ifdef __ATOMIC_SPINLOCK
			atomic_store(&(pool_ptr->atomic_spin_lock.avail), 0);
			atomic_store(&(pool_ptr->atomic_spin_lock.active), 1);
#else
			pthread_spin_init(&(pool_ptr->spin_lock), 0);
#endif
			syslog(LOG_DEBUG, "%s {o_pool:'%p', count_typeslots:'%d' count_types:'%d' pool_type_number:'%d' type_name:'%s'}: Expanded with new Type...", __func__,  pool_ptr, recycler_ptr->count_typeslots, recycler_ptr->count_types, pool_ptr->pool_handle.type, typename);
		}
	} else {
		//get idx of next available unoccupied slot for this new type
		recycler_ptr->count_types++;

		//allocate space for new type
		recycler_ptr->recyclers[recycler_ptr->count_types - 1] = calloc(1, sizeof(RecyclerPoolDefinition));
		pool_ptr = recycler_ptr->recyclers[recycler_ptr->count_types - 1];

		pool_ptr->pool_handle.type = recycler_ptr->count_types;

#ifdef __ATOMIC_SPINLOCK
			atomic_store(&(pool_ptr->atomic_spin_lock.avail), 0);
			atomic_store(&(pool_ptr->atomic_spin_lock.active), 1);
#else
		pthread_spin_init(&(pool_ptr->spin_lock), 0);
#endif

		syslog(LOG_DEBUG, "%s {o_pool:'%p', count_typeslots:'%d' count_types:'%d' pool_type:'%d', type_name:'%s'}: Recycler: Initialised empty slot...", __func__, pool_ptr, recycler_ptr->count_typeslots, recycler_ptr->count_types, pool_ptr->pool_handle.type, typename);
	}

	//create the first allocation group for the type
	if (pool_ptr) {
		//setup basic meta information
		pool_ptr->group_allocation_sz   = group_allocation_sz;
		pool_ptr->pool_handle.type_name = strdup(typename);
		pool_ptr->pool_handle.blocksz   = blocksz;
		memcpy (&(pool_ptr->ops), pool_ops_ptr, sizeof(RecyclerPoolOps));
		pool_ptr->expasnion_threshold   = expansion_threshold;

		//create the individual, yet unallocated memory slot pointers. Essentially, array of fixed size
		pool_ptr->pool_memory2 = calloc(group_allocation_sz, (sizeof(void *)));

		//create the individual, yet unallocated AllocationGroups, fixed size array Each groups gets assigned a slot, where it inflates itself into pool
		pool_ptr->allocation_groups = calloc(group_allocation_sz, sizeof(TypePoolAllocationGroup));

		//create the first allocation group, which attaches itself to the first available index in pool_memory
		RecyclerPoolHandle *pool_handle_ptr = _TypePoolExpandAllocationGroup(pool_ptr, group_allocation_sz);

		return pool_handle_ptr;

#if 0
		//aligned  sizeof(header)+blcksz
		//+-----------+=-----------+=------------+----------------
		// |client data
#endif

	} else {
		syslog(LOG_DEBUG, "%s {count_typeslots:'%d' count_types:'%d'}: ERROR: Recycle returned NULL PoolDefinition", __func__, recycler_ptr->count_typeslots, recycler_ptr->count_types);
	}

	return NULL;

}

/**
 * 	@brief: based on current allocated groups size 'pool_ptr->alocated_groups_sz' the Type's memory pool is expanded by adding an additional
 * 	allocation group. Type have fixed amount of allocation groups that they can expand into as set in the config file.
 * 	Each allocation group is a stand alone memory storage with its is own circular array queue.
 *
 * 	@locked: locking must be in place
 */
static RecyclerPoolHandle *
_TypePoolExpandAllocationGroup(RecyclerPoolDefinition *pool_ptr, size_t group_allocation_sz)
{
	if	(unlikely((pool_ptr->alocated_groups_sz >= group_allocation_sz))) {
		syslog (LOG_DEBUG, LOGSTR_RECYCLER_MAX_ALLOC_CAPACITY_REACHED, __func__, pthread_self(),  group_allocation_sz, pool_ptr->expasnion_threshold, LOGCODE_RECYCLER_MAX_ALLOC_CAPACITY_REACHED);

		return NULL;
	}

	//1)create actual storage for this point in the Type's parent structure. Note: allocated_groups_sz left at current position, otherwise we'd have to -1
	pool_ptr->pool_memory2[pool_ptr->alocated_groups_sz] = calloc(pool_ptr->expasnion_threshold, (sizeof(RecyclerPoolTypeEnvelop) + pool_ptr->pool_handle.blocksz));

	//2)create actual group's data/context holding structure at the sequentially indexed location
	pool_ptr->allocation_groups[pool_ptr->alocated_groups_sz] = calloc(1, sizeof(TypePoolAllocationGroup));

	//cast out (for  readability) the allocation group created above for further assignment
	TypePoolAllocationGroup *alloc_group_ptr = pool_ptr->allocation_groups[pool_ptr->alocated_groups_sz];

#if __VALGRIND_DRD
	VALGRIND_CREATE_MEMPOOL(alloc_group_ptr, 0, 1);
#endif

	//3) reference back to the storage memory chunk created under (1) + some sane initialisers
	alloc_group_ptr->groupid      = (pool_ptr->alocated_groups_sz * alloc_group_ptr->pool_size) + 1;//set at the boundary of the rid of the first object in the group
	alloc_group_ptr->pool_memory  = pool_ptr->pool_memory2[pool_ptr->alocated_groups_sz];
	alloc_group_ptr->leased_size  = 0;
	alloc_group_ptr->pool_size    = pool_ptr->expasnion_threshold;
#ifdef __ATOMIC_SPINLOCK
			atomic_store(&(alloc_group_ptr->atomic_spin_lock.avail), 0);
			atomic_store(&(alloc_group_ptr->atomic_spin_lock.active), 1);
#else
	pthread_spin_init(&(alloc_group_ptr->spin_lock), 0);
#endif
	//4)create the queue for this allocation group: fixed-sized  array  (pool_size) referencing each memory chunk under (5)
	alloc_group_ptr->pool_queue = calloc(alloc_group_ptr->pool_size, sizeof(RecyclerPoolTypeEnvelop *));//a pointer-slot for each type instance
	alloc_group_ptr->head       = alloc_group_ptr->tail = 0;

	//5)sequentially map out and delineate individual memory chunks(header+client data) on storage created under (1)
	//it is here where each chunk is identified with permanent id
  RecyclerPoolTypeEnvelop *ptr;
  char *p;

  size_t i;
  for (i=0; i<alloc_group_ptr->pool_size; i++) {
    ptr = alloc_group_ptr->pool_memory + (i * (pool_ptr->pool_handle.blocksz + sizeof(RecyclerPoolTypeEnvelop)));
    alloc_group_ptr->pool_queue[i] = ptr;
    //atomic_store_explicit(&(ptr->_refcount), 1, memory_order_release);
    atomic_init (&(ptr->_refcount), 1);
    ptr->oid = i + 1 + (pool_ptr->alocated_groups_sz * alloc_group_ptr->pool_size);

    p = (char *)ptr;
    p += sizeof(RecyclerPoolTypeEnvelop);

    //no InstanceHolder ref available yet
    if (RECYCLER_TYPE_INIT_CALLBACK(pool_ptr)) {
      if (likely((((pool_ptr->ops.poolop_init_callback)((ClientContextData *)p, ptr->oid)) == 0))) {
        //nothing at this stage
      }
    }
  }

  //alloc_group_ptr->head=0;
  _PrintQueueEntry (pool_ptr, alloc_group_ptr, alloc_group_ptr->pool_queue[alloc_group_ptr->head]);
  //alloc_group_ptr->tail=alloc_group_ptr->pool_size-1;
  _PrintQueueEntry (pool_ptr, alloc_group_ptr, alloc_group_ptr->pool_queue[alloc_group_ptr->tail]);

	//from now on, index this group at pool_ptr->alocated_groups_sz-1
	pool_ptr->alocated_groups_sz++;
	RECYCLER_POOL_CURRENT_MAX_CAPACITY(pool_ptr) = pool_ptr->alocated_groups_sz * pool_ptr->expasnion_threshold;

	syslog(LOG_DEBUG, LOGSTR_RECYCLER_ALLOC_GROUP_EXPANDED, __func__, pool_ptr->pool_handle.type_name, alloc_group_ptr->groupid, alloc_group_ptr->head, alloc_group_ptr->tail, pool_ptr->expasnion_threshold, pool_ptr->pool_handle.blocksz, group_allocation_sz, RECYCLER_POOL_CURRENT_MAX_CAPACITY(pool_ptr), LOGCODE_RECYCLER_ALLOC_GROUP_EXPANDED);

#if __VALGRIND_DRD
	//this memory pool chunk is now handed over to valgrind for monitoring. Any access is invalid unless  individual type chunks are allocated via RecyclerGet/RecyclerPut
	VALGRIND_MAKE_MEM_NOACCESS(pool_ptr->pool_memory2[pool_ptr->alocated_groups_sz-1], pool_ptr->expasnion_threshold * (sizeof(RecyclerPoolTypeEnvelop) + pool_ptr->pool_handle.blocksz));
#endif

	return &(pool_ptr->pool_handle);//fixed memory location relative to pool

}

static inline
RecyclerPoolTypeEnvelop *DeriveHeaderEnvelopeFromInstanceHolder (InstanceHolder *instance_holder_ptr)
{
  ClientContextData *context_data_ptr = GetInstance(instance_holder_ptr);
  char *p = (char *)context_data_ptr;
  p -= sizeof(RecyclerPoolTypeEnvelop);

  return (RecyclerPoolTypeEnvelop *)p;
}

/**
 * retrieving the group array index based on elementary matrix math
 * address(array index)=col+ row*number of columns
 * row=address/number of columns --> C will return the floor of the integer division which is the index/address
 * col=address-row*number of columns
 */
static inline TypePoolAllocationGroup *
_TypePoolAllocationGroupGet (RecyclerPoolDefinition *pool_ptr, RecyclerPoolTypeEnvelop *env_ptr)
{
	size_t oid = env_ptr->oid;
	if (likely((oid > 0) && (oid <= RECYCLER_POOL_CURRENT_MAX_CAPACITY(pool_ptr)))) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu, rid:'%lu', pool_sz:'%u', allocation_group_idx:'%lu'}: Retrieved AllocationGroup index...", __func__, pthread_self(),  env_ptr->oid, RECYCLER_POOL_CHUNK_SZ(pool_ptr), (oid-1)/RECYCLER_POOL_CHUNK_SZ(pool_ptr));
#endif
		return RECYCLER_POOL_ALLOCATION_GROUP(pool_ptr, (oid -1 ) / RECYCLER_POOL_CHUNK_SZ(pool_ptr));

#if 0
		//fallback stupid, bruteforce method for validation testing
		int i;
		for (i=1, i<pool_ptr->alocated_groups_sz; i++)
		{
			size_t boundary_factor=i*RECYCLER_POOL_CHUNK_SZ(pool_ptr);
			if (oid>=boundary_factor-(boundary_factor-1) && i<=boundary_factor)	break;
		}

		syslog(LOG_DEBUG, "%s {pid:'%lu, allocation_group:'%d'}", pthread_self(), i);

		if (unlikely(i>RECYCLER_POOL_ALLOCATED_GROUPS_SZ(pool_ptr)))	return NULL;

		return RECYCLER_POOL_ALLOCATION_GROUP(pool_ptr, i);
#endif
	}

	syslog(LOG_DEBUG, LOGSTR_RECEYCLER_ALLOC_GROUP_IDX_ERR, __func__, pthread_self(),  env_ptr->oid, RECYCLER_POOL_CHUNK_SZ(pool_ptr), oid/RECYCLER_POOL_CHUNK_SZ(pool_ptr), LOGCODE_RECEYCLER_ALLOC_GROUP_IDX_ERR);

	return NULL;

}

/**
 * 	@brief: boundary condition is done in calling environment ie. whether enqueueu'ed elements at full capacity
 * 	@locked:	locked in the calling environment
 */
static inline void
_EnQueue (RecyclerPoolHandle *pool_handle, TypePoolAllocationGroup *alloc_group_ptr, RecyclerPoolTypeEnvelop *env_ptr)
{
	char *p;
	p = (char *)env_ptr;
	p += sizeof(RecyclerPoolTypeEnvelop);

	//update queue slot with mem chunk
	alloc_group_ptr->pool_queue[alloc_group_ptr->tail] = env_ptr;

	//push tail back. boundary condition already checked
	alloc_group_ptr->tail = (alloc_group_ptr->tail + 1) % alloc_group_ptr->pool_size;

	alloc_group_ptr->leased_size--;

	syslog (LOG_DEBUG, LOGSTR_RECYCLER_ENQUE_SUCCESS, __func__, pthread_self(), alloc_group_ptr->groupid, alloc_group_ptr->tail, alloc_group_ptr->head, p, env_ptr->oid, pool_handle->type_name, alloc_group_ptr->leased_size, LOGCODE_RECYCLER_ENQUE_SUCCESS);

}

/**
 * 	@locked: AllocationGroup must be locked in the calling environment
 * 	TODO: pool_ptr is not need, but we can still pass the pool_handle
 */
static inline
RecyclerPoolTypeEnvelop *_DeQueue (RecyclerPoolHandle *pool_handle, TypePoolAllocationGroup *alloc_group_ptr)
{
	if (unlikely(alloc_group_ptr == NULL)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', e:'%d'}: ERROR: NULL PARAMETER:'%s'", __func__, pthread_self(), LOGCODE_RECYCLER_UNDEFINED_GROUPALLOC, "Undefined AllocationGroup *");

		return NULL;
	}

	RecyclerPoolTypeEnvelop *env_ptr = alloc_group_ptr->pool_queue[alloc_group_ptr->head];

#if __VALGRIND_DRD
		//any later than here valgrind will bark, as we start accessing different memory addresses within the chunk
		VALGRIND_MEMPOOL_ALLOC(alloc_group_ptr, env_ptr, sizeof(RecyclerPoolTypeEnvelop)+pool_handle->blocksz);
#endif

	char *p;
	p = (char *)env_ptr;
	p += sizeof(RecyclerPoolTypeEnvelop);
//	RecyclerClientData *client_data = (RecyclerClientData *)p;

	//trap queue pointers overrun indirectly we could be be pointing at a leased item
	//if (env_ptr->refcount!=1)
	size_t	refcount_read;
	if ((refcount_read = atomic_load_explicit(&(env_ptr->_refcount), memory_order_acquire)) != 1) {
		syslog(LOG_DEBUG, LOGSTR_RECYCLER_QUEUE_ITEM_REFCOUNT_ERROR, __func__, pthread_self(), ALLOCGROUP_TAIL(alloc_group_ptr), ALLOCGROUP_HEAD(alloc_group_ptr), p, env_ptr->oid, refcount_read/*env_ptr->refcount*/, pool_handle->type_name, ALLOCGROUP_LEASEDSIZE(alloc_group_ptr), LOGCODE_RECYCLER_QUEUE_ITEM_REFCOUNT_ERROR,
				"ITEM NOT DEQUEUED");

#if __VALGRIND_DRD
		//give it back
		VALGRIND_MEMPOOL_FREE(alloc_group_ptr, env_ptr);
#endif

		return NULL;//up to caller to abort whatever they were doing, for example close socket
	}

	alloc_group_ptr->head = (alloc_group_ptr->head + 1) % alloc_group_ptr->pool_size;

	alloc_group_ptr->leased_size++;

	syslog (LOG_DEBUG, LOGSTR_RECYCLER_DEQUE_SUCCESS, __func__, pthread_self(), alloc_group_ptr->groupid, alloc_group_ptr->tail, alloc_group_ptr->head, p, env_ptr->oid, pool_handle->type_name, alloc_group_ptr->leased_size, LOGCODE_RECYCLER_DEQUE_SUCCESS);

	return env_ptr;

}

//enqueue
/**
 * @brief: add a free item to the queue, available for reuse
 * The last user, implicitly calls Put to decrement refcount. ie refcount must be 2
 */
int
RecyclerPut(const unsigned type, InstanceHolder *client_data, ContextData *context_data, unsigned long call_flags)
{
	int rc = 0;
	TypePoolAllocationGroup *alloc_group_ptr = NULL;

	RecyclerPoolDefinition *pool_ptr = recycler_ptr->recyclers[type - 1];

	if (unlikely(IS_EMPTY(pool_ptr))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', e:'%d'}: ERROR: NULL PARAMETER:'%s'", __func__, pthread_self(), LOGCODE_RECYCLER_UNDEFINED_POOLDEF, "Undefined RecyclerPoolDefinition *");

		return -1;
	}

  if (unlikely(IsMarshaller(client_data))) {
    syslog (LOG_DEBUG, LOGSTR_RECYCLER_MARSHALLER_INSTANCE, __func__, pthread_self(), client_data, GetMarshaller(client_data), LOGCODE_RECYCLER_MARSHALLER_INSTANCE);

    rc = -5;

    goto exit_error;
  }

	//TODO: slightly aggressive.. might revise later on
	pthread_spin_lock(&(pool_ptr->spin_lock));

//	char *p;
//	DeriveHeaderEnvelopeFromInstanceHolder()
//	p = (char *)GetInstance(client_data);//client_data->holder.instance;
//	p -= sizeof(RecyclerPoolTypeEnvelop);
//	RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;

  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder(client_data/*instance_holder_ptr*/);
	//find the corresponding allocation group for the rid. Important indexing is kept at utmost consistency

	if (unlikely((alloc_group_ptr = _TypePoolAllocationGroupGet(pool_ptr, env_ptr)) == NULL)) {
		pthread_spin_unlock(&(pool_ptr->spin_lock));

		return -1;
	}

	pthread_spin_lock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));

	//positively optimistic

	size_t refcount_read;
	if (((refcount_read = atomic_load_explicit(&(env_ptr->_refcount), memory_order_acquire))-1) != 1) {
		syslog (LOG_DEBUG, LOGSTR_RECYCLER_ENQUE_REFCNT_SHORT, __func__, alloc_group_ptr->tail, refcount_read, client_data, env_ptr->oid, pool_ptr->pool_handle.type_name, alloc_group_ptr->leased_size, LOGCODE_RECYCLER_ENQUE_REFCNT_SHORT);
		rc = -3;

		goto exit_error;
	}

	//this is  a major stuff up and should not really happen, because it is a bounded system with controlled capacity
	//if ((pool_ptr->tail + 1) % pool_ptr->pool_size==pool_ptr->head)
	if (alloc_group_ptr->leased_size == 0) {
		syslog (LOG_DEBUG, LOGSTR_RECYCLER_PUT_ON_FULL, __func__, pthread_self(), alloc_group_ptr->head, alloc_group_ptr->tail, pool_ptr->pool_handle.type_name, alloc_group_ptr->leased_size, LOGCODE_RECYCLER_PUT_ON_FULL);

		rc = -2;

		goto exit_error;//todo: imlement expansion?
	}

	if (ILIST_SIZE(&env_ptr->instances_list) > 1) {
	  //user should collect all instances that are about in the system
    syslog (LOG_DEBUG, LOGSTR_RECYCLER_UNCOLLECTED_INSTANCE, __func__, pthread_self(), alloc_group_ptr->groupid, alloc_group_ptr->tail, alloc_group_ptr->head, env_ptr, env_ptr->oid, pool_ptr->pool_handle.type_name, alloc_group_ptr->leased_size, env_ptr->instances_list.size, LOGCODE_RECYCLER_UNCOLLECTED_INSTANCES);

    rc = -4;

    goto exit_error;
	}

	if (RECYCLER_TYPE_INITPUT_CALLBACK(pool_ptr)) {
		RECYCLER_TYPE_INITPUT_CALLBACK_INVOKE(pool_ptr, client_data, context_data, call_flags);
	}
  int found = RemoveThisInstanceFromList(&(env_ptr->instances_list), client_data);
	if (!found) {
	  //too late to recover, but this is major stuff up
    syslog (LOG_DEBUG, LOGSTR_RECYCLER_UNCOLLECTED_INSTANCE, __func__, pthread_self(), alloc_group_ptr->groupid, alloc_group_ptr->tail, alloc_group_ptr->head, env_ptr, env_ptr->oid, pool_ptr->pool_handle.type_name, alloc_group_ptr->leased_size, env_ptr->instances_list.size, LOGCODE_RECYCLER_INSTANCE_NOT_ON_LIST);
    //todo mark instance as faulty?
	}

	_EnQueue(RECYCLER_POOL_HANDLE_PTR(pool_ptr), alloc_group_ptr, env_ptr);

	atomic_store_explicit(&(env_ptr->_refcount), 1, memory_order_release);

#if __VALGRIND_DRD
	//do it last, just before unlocking to ensure block doesnt get allocated by another thread
		VALGRIND_MEMPOOL_FREE(alloc_group_ptr, env_ptr);
#endif

	pthread_spin_unlock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));
	pthread_spin_unlock(&(pool_ptr->spin_lock));

	return 0;//success

	exit_error:
	pthread_spin_unlock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));
	pthread_spin_unlock(&(pool_ptr->spin_lock));

	return rc;

}

#ifdef __ATOMIC_SPINLOCK
inline static void
SpinLock(atomic_spinlock_t *spinlock)
{
	/*
	unsigned int placeholder=atomic_fetch_add(&(spinlock->avail));

	while (atomic_load(&(spinlock->active)) != placeholder) {
	    //Wait for my turn
	    SPINWAIT();
	}
	atomic_thread_fence(memory_order_seq_cst); // Sync memory.*/

	//using acquire-release model
	unsigned int placeholder=atomic_fetch_add_explicit(&(spinlock->avail), memory_order_acq_rel);
	while (atomic_load(&(spinlock->active), memory_order_acquire) != placeholder)
	{
	    // Wait for my turn.
	    SPINWAIT();
	}
}

inline static void
SpinUnLock (atomic_spinlock_t *spinlock)
{
	//atomic_thread_fence(memory_order_seq_cst); /* Sync memory. */
	//atomic_fetch_add(&(spinnlock->active), 1);

	atomic_fetch_add(&(spinnlock->active), 1, memory_order_release);
}

#endif

//dequeue
/**
 * 	@brief:	retrieve an available item from the queue and apply lifecycle callback
 * 	@param context_data caller context data to be passed when instance is successfully created from a given type
 */
InstanceHolder *
RecyclerGet (const unsigned type, ContextData *context_data, unsigned long call_flags)
{
	RecyclerPoolTypeEnvelop *env_ptr				= NULL;
	ClientContextData 			*client_data		= NULL;
	TypePoolAllocationGroup *alloc_group_ptr= NULL;

	RecyclerPoolDefinition *pool_ptr = (recycler_ptr->recyclers[type - 1]);

	if (unlikely(IS_EMPTY(pool_ptr))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', e:'%d'}: ERROR: NULL PARAMETER:'%s'", __func__, pthread_self(), LOGCODE_RECYCLER_UNDEFINED_POOLDEF, "Undefined RecyclerPoolDefinition *");

		return NULL;
	}

	//TODO: potentially aggressive revise, but we need to ensure the state of the leased items do not change after we identified one
	//we also don't want the TypePool to trigger expansion on us, because that changes the value of RECYCLER_POOL_ALLOCATED_GROUPS_SZ
	//but we could still operate on a snapshot, because when expansion happens that happens after the RECYCLER_POOL_ALLOCATED_GROUPS_SZ index we read here so that is OK concurrency wise
	pthread_spin_lock(&(pool_ptr->spin_lock));

	//get the first Allocation group that has available, non-leased entry
	find_available_allocation_group:
	{
		int i;
		for (i=0; i<RECYCLER_POOL_ALLOCATED_GROUPS_SZ(pool_ptr); i++) {
			//we have unleased items
			if (RECYCLER_POOL_ALLOCATION_GROUP(pool_ptr, i)->leased_size < RECYCLER_POOL_ALLOCATION_GROUP(pool_ptr, i)->pool_size) {
				alloc_group_ptr = RECYCLER_POOL_ALLOCATION_GROUP(pool_ptr, i);
				break;
			}
		}
	}

	if (IS_EMPTY(alloc_group_ptr)) {
		//TODO: TRIGGER EXPANSION and check position spinlock for pool below, as we'd need to keep it locked during expansion
		syslog(LOG_DEBUG, LOGSTR_RECYCLER_GET_FULLY_LEASED, __func__, pthread_self(), RECYCLER_POOL_TYPENAME(pool_ptr), RECYCLER_POOL_ALLOCATED_GROUPS_SZ(pool_ptr), LOGCODE_RECYCLER_GET_FULLY_LEASED);
		if (_TypePoolExpandAllocationGroup(pool_ptr, pool_ptr->group_allocation_sz))	goto find_available_allocation_group;
		else	goto exit_error;//unlocks spin_lock
	}

	pthread_spin_unlock(&(pool_ptr->spin_lock));

	/*if  (pool_ptr->leased_size==pool_ptr->pool_size)//(pool_ptr->head == pool_ptr->tail)
	{
		syslog(LOG_DEBUG, LOGSTR_RECYCLER_GET_FULLY_LEASED, __func__, pthread_self(), pool_ptr->pool_handle.type_name, pool_ptr->leased_size, LOGCODE_RECYCLER_GET_FULLY_LEASED);

		goto exit_error;
	}
	else*/
	{
		pthread_spin_lock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));

		//perhaps we can be forgiven for being confident after all preceding checks
		if (unlikely((env_ptr = _DeQueue(RECYCLER_POOL_HANDLE_PTR(pool_ptr), alloc_group_ptr)) == NULL)) {
			pthread_spin_unlock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));

			return NULL;//pool_ptr is unlocked
		}

		char *p;
		p = (char *)env_ptr;
		p += sizeof(RecyclerPoolTypeEnvelop);
		client_data = (ClientContextData *)p; //pool allocation slot for actual desired object (session, fence etc..)
		atomic_fetch_add_explicit(&(env_ptr->_refcount), 1, memory_order_acq_rel);

    ListItemInstance *list_item_ptr = AddThisInstanceToList(&(env_ptr->instances_list), client_data);

#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {pid:'%lu', o_instance:'%p', o:'%p'}: InstanceHolder set...", __func__, pthread_self(), &(list_item_ptr->item), client_data);
#endif

    if (RECYCLER_TYPE_INITGET_CALLBACK(pool_ptr)) {
			if (!(RECYCLER_TYPE_INITGET_CALLBACK_INVOKE(pool_ptr, CLIENT_CTX_DATA(ILIST_ITEM_PTR(list_item_ptr))/*client_data*/, context_data, env_ptr->oid, call_flags) == 0)) {
//        RemoveFromInstancesList(&(env_ptr->instances_list), list_item_ptr); //don't do this here, as we lose reference to the InstanceHolder. This is done in RecyclerPut()
				atomic_fetch_sub_explicit(&(env_ptr->_refcount), 1, memory_order_acq_rel);

				pthread_spin_unlock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));//gets locked in the function below

				RecyclerPut(type, ILIST_ITEM_PTR(list_item_ptr), (ContextData *)NULL, CALLFLAGS_EMPTY);

				return NULL;//up to caller to abort whatever they were doing, for example close socket
			}
		}

		exit_success:
		pthread_spin_unlock(ALLOCGROUP_SPINLOCK_PTR(alloc_group_ptr));

		return ILIST_ITEM_PTR(list_item_ptr);//client_data;
	}

	exit_error:

	pthread_spin_unlock(&(pool_ptr->spin_lock));

	return NULL;

}

/**
 * @brief Given a pool object of a given type, create a new instance holder to reference the object.
 * IMPORTANT: caller's responsibility to ensure no concurrent call is being done. Therefore some locking is needed.
 * @param instance_holder_ptr A pool object previously obtained from the pool. Must be in 'instance state'. Used to access envelope header
 * @return A new InstanceHolder referencing the pool object.
 */
InstanceHolder *
RecyclerGetNewInstance (InstanceHolder *instance_holder_ptr)
{
//  ClientContextData *context_data_ptr = GetInstance(instance_holder_ptr);
//  char *p = (char *)context_data_ptr;
//  p -= sizeof(RecyclerPoolTypeEnvelop);
//  RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;

  ClientContextData *context_data_ptr = GetInstance(instance_holder_ptr);
  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder (instance_holder_ptr);
  ListItemInstance *list_item_ptr = AddThisInstanceToList (&(env_ptr->instances_list), CLIENT_CTX_DATA(context_data_ptr));
  if (IS_PRESENT(list_item_ptr)) {
    return ILIST_ITEM_PTR(list_item_ptr);
  }

  syslog(LOG_DEBUG, LOGSTR_RECYCLER_NEW_INSTANCE_ERROR, __func__, pthread_self(), context_data_ptr, LOGCODE_RECYCLER_NEW_INSTANCE_ERROR);
  return NULL;

}

/**
 * IMPORTANT: THIS IS TEMPORARY UNTIL RELEVANT METHOD SIGNATURES ARE UPDATED TO HAVE DIRECT InstanceHolder REFERENCE PASSED INTO THEM
 * @brief Retrieve the InstanceHolder reference for a given pool managed type. Assumes one instance refernce per pool object
 * @param ctx_ptr Pool managed type
 * @return
 */
InstanceHolder *
InstanceHolderFromClientContext (ContextData *ctx_ptr)
{
  char *p = (char *)ctx_ptr;
	p -= sizeof(RecyclerPoolTypeEnvelop);
	RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;
	if (env_ptr->instances_list.size == 0)  {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'} ERROR: Instance List empty", __func__, pthread_self(), ctx_ptr);
	  return NULL;
	}

	assert(env_ptr->instances_list.head == env_ptr->instances_list.tail);

	return &(env_ptr->instances_list.head->item);
}

/**
 * @brief Given an InstanceHolder derive the underlying recycler-managed object (AKA ClientContextData) which it references.
 * One ClientContextData can have one-or-more InstanceHolder references.
 * @param instance_holder_ptr
 * @return recycler-managed object, AKA ClientContextData
 */
ClientContextData *
GetClientContextData (InstanceHolder *instance_holder_ptr)
{
  return GetInstance(instance_holder_ptr);
}

int
RecyclerDestroyInstance (InstanceHolder *instance_holder_ptr)
{
//  ClientContextData *context_data_ptr = GetInstance(instance_holder_ptr);
//  char *p = (char *)context_data_ptr;
//  p -= sizeof(RecyclerPoolTypeEnvelop);
//  RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;

  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder (instance_holder_ptr);

  int found = RemoveThisInstanceFromList (&(env_ptr->instances_list), instance_holder_ptr);
  if (!found) {
    ClientContextData *context_data_ptr = GetInstance(instance_holder_ptr);
    syslog(LOG_DEBUG, LOGSTR_RECYCLER_INSTANCE_NOT_ON_LIST, __func__, pthread_self(), instance_holder_ptr, context_data_ptr, LOGCODE_RECYCLER_INSTANCE_NOT_ON_LIST);

    return INSTANCE_HOLDER_NOT_FOUND;
  }

  return INSTANCE_HOLDER_FOUND;

}

/**
 * debug
 */
static inline void
_PrintQueueEntry (RecyclerPoolDefinition *pool_ptr, TypePoolAllocationGroup *alloc_group_ptr, RecyclerPoolTypeEnvelop *env_ptr)
{
	char *p;
	p = (char *)env_ptr;
	p += sizeof(RecyclerPoolTypeEnvelop);

	syslog (LOG_DEBUG, "%s {o:'%p', rid:'%lu', refcount:'%lu', type_name:'%s, leased_sz:'%lu'}: Recycler: RETRIEVED (DEQUEUE) FROM POOL...",
			__func__, p, env_ptr->oid, atomic_load_explicit(&(env_ptr->_refcount), memory_order_acquire)/*(env_ptr->refcount*/, pool_ptr->pool_handle.type_name, alloc_group_ptr->leased_size);

}

size_t
RecyclerTypeGetReferenceCount (unsigned type, InstanceHolder *instance_holder_ptr)
{
//	char *p;
//	p = (char *)client_data;
//	p -= sizeof(RecyclerPoolTypeEnvelop);
//	RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;

  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder (instance_holder_ptr);
	size_t refcount;
	refcount = atomic_load_explicit(&(env_ptr->_refcount), memory_order_acquire);//todo: perhaps use relaxed semantics

	return refcount;
}

void
RecyclerTypeReferenced (unsigned type, InstanceHolder *instance_holder_ptr, int multiples)
{
//	char *p;
//	p = (char *)client_data;
//	p -= sizeof(RecyclerPoolTypeEnvelop);
//	RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;
  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder (instance_holder_ptr);
	atomic_fetch_add_explicit(&(env_ptr->_refcount), multiples, memory_order_acq_rel);
}

void
RecyclerTypeUnReferenced (unsigned type, InstanceHolder *instance_holder_ptr, int multiples)
{
//	char *p;
//	p = (char *)client_data;
//	p -= sizeof(RecyclerPoolTypeEnvelop);
//	RecyclerPoolTypeEnvelop *env_ptr = (RecyclerPoolTypeEnvelop *)p;
  RecyclerPoolTypeEnvelop *env_ptr = DeriveHeaderEnvelopeFromInstanceHolder (instance_holder_ptr);
	atomic_fetch_sub_explicit(&(env_ptr->_refcount), multiples, memory_order_acq_rel);

}

static bool
IsRecyclerTypeQueueEmpty (unsigned type, TypePoolAllocationGroup *alloc_group_ptr)
{
	RecyclerPoolDefinition *pool_ptr = (recycler_ptr->recyclers[type-1]);
	pthread_spin_lock(&(pool_ptr->spin_lock));
	bool rc = ((alloc_group_ptr->tail + 1)% alloc_group_ptr->pool_size == alloc_group_ptr->head);
	pthread_spin_unlock(&(pool_ptr->spin_lock));

	return rc;
}

static bool
IsRecyclerTypeQueueFull (unsigned type, TypePoolAllocationGroup *alloc_group_ptr)
{

	RecyclerPoolDefinition *pool_ptr=(recycler_ptr->recyclers[type-1]);
	pthread_spin_lock(&(pool_ptr->spin_lock));
	bool rc = (alloc_group_ptr->head == alloc_group_ptr->tail);
	pthread_spin_unlock(&(pool_ptr->spin_lock));

	return rc;
}

#if 0
extern SessionsDelegator *const sessions_delegator_ptr;

void *
FetchRecycledObject(void)
{
	if ((RecycledSessions_WrLock(1)) != 0) {
		 syslog(LOG_NOTICE, "%s: ERROR: COULD NOT WRLOCK RECYCLER QUEUE", __func__);

		 return NULL;
	}

	if (sessions_delegator_ptr->recycled_sessions.queue.nEntries > 0) {
		QueueEntry *qe_ptr = NULL;

		qe_ptr = deQueue(&(sessions_delegator_ptr->recycled_sessions.queue));
		syslog(LOG_DEBUG, "%s: SUCCESS: FETCHED object (ro: '%p' rid: '%lu') from Recycler. Current nEntries: '%lu'...",__func__, qe_ptr->whatever, ((Session *)qe_ptr->whatever)->recycler_id, sessions_delegator_ptr->recycled_sessions.queue.nEntries);

		//statsd_dec(((Session *)qe_ptr->whatever)->instrumentation_backend, "sessions.recyled", 1.0);
		//statsd_gauge(((Session *)qe_ptr->whatever)->instrumentation_backend, "sessions.recyled", sessions_delegator_ptr->recycled_sessions.queue.nEntries);

		RecycledSessions_UnLock();

		return qe_ptr->whatever;
	} else {
		syslog(LOG_DEBUG, "%s: queue is empty...", __func__);
	}

	RecycledSessions_UnLock();

	return NULL;

}

inline static int
RecycledSessions_RdLock (unsigned try_flag)
{
	int lock_state;

		if (try_flag) {
			lock_state = pthread_rwlock_tryrdlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));
			if (lock_state == 0) syslog(LOG_DEBUG, "%s: SUCCESS: TRY-READ lock for Session events acquired...", __func__);
			else {
				char error_str[250];
				strerror_r(errno, error_str, 250);

				syslog(LOG_NOTICE, "%s: ERROR: COULD NOT acquire TRY-READ lock for Session events (errno='%d'):  '%s'",__func__, errno, error_str);
			}
		} else {
		  lock_state = pthread_rwlock_rdlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));

			if (lock_state == 0) syslog(LOG_INFO, "%s: SUCCESSFULLY acquired READ lock", __func__);
			else {
				char error_str[250];
				strerror_r(errno, error_str, 250);
				syslog(LOG_NOTICE, "%s: ERROR: COULD NOT acquire READ lock: error: '%s'", __func__, error_str);
			}
		}

		return lock_state;

}

inline static int
RecycledSessions_WrLock (unsigned try_flag)
{
	int lock_state;

	if (try_flag) {
		lock_state = pthread_rwlock_tryrdlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));
		if (lock_state == 0) syslog(LOG_DEBUG, "RecycledSessions_WRLock: SUCCESS: TRY-WR lock for Session events acquired...");
		else {
			char error_str[250];
			strerror_r(errno, error_str, 250);

			syslog(LOG_NOTICE, "%s: ERROR: COULD NOT acquire TRY-WR lock for Session events (errno='%d'):  '%s'", __func__, errno, error_str);
		}
	} else {
		lock_state = pthread_rwlock_wrlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));

		if (lock_state == 0) syslog(LOG_DEBUG, "%s: SUCCESSFULLY acquired WR lock", __func__);
		else {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_NOTICE, "%s: ERROR: COULD NOT acquire WR lock: error: '%s'", __func__, error_str);
		}

	}

	return lock_state;

#if 0
	int lock_state = pthread_rwlock_wrlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));

	if (lock_state==0) syslog(LOG_INFO, "RecycledSessions_RdLock: SUCCESSFULLY acquired WRITE lock...");
	else
	{
		char error_str[250];
		strerror_r(errno, error_str, 250);
		syslog(LOG_INFO, "RecycledSessions_RdLock: COULD NOT acquire WRITE lock: error: '%s'", error_str);
	}
#endif

}

inline static void
RecycledSessions_UnLock (void)
{
	int lock_state = pthread_rwlock_unlock(&(sessions_delegator_ptr->recycled_sessions.queue_rwlock));

	if (lock_state == 0) syslog(LOG_INFO, "%s: SUCCESSFULLY released lock...", __func__);
	else {
		char error_str[250];
		strerror_r(errno, error_str, 250);
		syslog(LOG_INFO, "%s: COULD NOT release lock: error: '%s'", __func__, error_str);
	}

}
#endif
