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

#ifndef SRC_INCLUDE_RECYCLER_H_
#define SRC_INCLUDE_RECYCLER_H_

#include <stdatomic.h>
#include "instance_type.h"
#include "recycler_type.h"

#define INSTANCE_HOLDER_FOUND     1
#define INSTANCE_HOLDER_NOT_FOUND 0

int AddReceycledObject (void *ro_ptr);
void *FetchRecycledObject(void);

RecyclerPoolHandle *
RecyclerInitTypePool(const char *typename, size_t blocksz, size_t group_allocation_sz, size_t expansion_threshold,
                     RecyclerPoolOps *pool_ops_ptr);
int RecyclerPut(const unsigned type, InstanceHolder *, ContextData *, unsigned long);
InstanceHolder *RecyclerGet(const unsigned type, ContextData *, unsigned long);

InstanceHolder *RecyclerGetNewInstance (InstanceHolder *instance_holder_ptr);
int RecyclerDestroyInstance (InstanceHolder *instance_holder_ptr);
ClientContextData *GetClientContextData (InstanceHolder *);
InstanceHolder *InstanceHolderFromClientContext (ContextData *ctx_ptr);

void RecyclerTypeReferenced (unsigned type, InstanceHolder *client_data, int);
void RecyclerTypeUnReferenced (unsigned type, InstanceHolder *client_data, int);
size_t RecyclerTypeGetReferenceCount (unsigned type, InstanceHolder *client_data);

#if 0
//we can't do this at the moment because types are private to recycler.c
static inline size_t
RecyclerTypeGetReferenceCount (unsigned type, RecyclerClientData *client_data)
{
	char *p;
	p=(char *)client_data;
	p-=sizeof(RecyclerPoolTypeEnvelop);
	RecyclerPoolTypeEnvelop *env_ptr=(RecyclerPoolTypeEnvelop *)p;

	size_t refcount;
	refcount=atomic_load_explicit(&(env_ptr->_refcount), memory_order_acquire);//todo: perhaps can use relaxed semantics

	return refcount;
}


static inline void
RecyclerTypeReferenced (unsigned type, RecyclerClientData *client_data, int multiples)
{
#if 0
	TypePoolAllocationGroup *alloc_group_ptr=NULL;
	RecyclerPoolDefinition *pool_ptr=(recycler_ptr->recyclers[type-1]);

	char *p;
	p=(char *)client_data;
	p-=sizeof(RecyclerPoolTypeEnvelop);
	RecyclerPoolTypeEnvelop *env_ptr=(RecyclerPoolTypeEnvelop *)p;

	pthread_spin_lock(&(pool_ptr->spin_lock));
	if (unlikely((alloc_group_ptr=_TypePoolAllocationGroupGet(pool_ptr, env_ptr))==NULL))
	{
		pthread_spin_unlock(&(pool_ptr->spin_lock));

		return;
	}
	pthread_spin_unlock(&(pool_ptr->spin_lock));

	pthread_spin_lock(&(alloc_group_ptr->spin_lock));
	env_ptr->refcount+=multiples;
	pthread_spin_unlock(&(alloc_group_ptr->spin_lock));
#endif

	char *p;
	p=(char *)client_data;
	p-=sizeof(RecyclerPoolTypeEnvelop);
	RecyclerPoolTypeEnvelop *env_ptr=(RecyclerPoolTypeEnvelop *)p;

	atomic_fetch_add_explicit(&(env_ptr->_refcount), multiples, memory_order_acq_rel);
}


static inline void
RecyclerTypeUnReferenced (unsigned type, RecyclerClientData *client_data, int multiples)
{
#if 0
	TypePoolAllocationGroup *alloc_group_ptr=NULL;
		RecyclerPoolDefinition *pool_ptr=(recycler_ptr->recyclers[type-1]);

		char *p;
		p=(char *)client_data;
		p-=sizeof(RecyclerPoolTypeEnvelop);
		RecyclerPoolTypeEnvelop *env_ptr=(RecyclerPoolTypeEnvelop *)p;

		pthread_spin_lock(&(pool_ptr->spin_lock));
		if (unlikely((alloc_group_ptr=_TypePoolAllocationGroupGet(pool_ptr, env_ptr))==NULL))
		{
			pthread_spin_unlock(&(pool_ptr->spin_lock));

			return;
		}
		pthread_spin_unlock(&(pool_ptr->spin_lock));

		pthread_spin_lock(&(alloc_group_ptr->spin_lock));
		env_ptr->refcount-=multiples;
		pthread_spin_unlock(&(alloc_group_ptr->spin_lock));
#endif

	char *p;
	p=(char *)client_data;
	p-=sizeof(RecyclerPoolTypeEnvelop);
	RecyclerPoolTypeEnvelop *env_ptr=(RecyclerPoolTypeEnvelop *)p;
	atomic_fetch_sub_explicit(&(env_ptr->_refcount), multiples, memory_order_acq_rel);

}
#endif

#endif /* SRC_INCLUDE_RECYCLER_H_ */
