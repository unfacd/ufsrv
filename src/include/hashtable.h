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

#ifndef INCLUDE_HASHTABLE_H_
#define INCLUDE_HASHTABLE_H_

#include <recycler_type.h>
#include <cdt_optik_lock.h>

typedef ClientContextData * (*ItemExtractor)(ItemContainer *);

typedef struct HashTable
{
	void	**fTable;//user data
	size_t	fTableSize;//dynamically growing capacity
	size_t	max_size; //ceiling on growing capacity. Also used as fixed size when non resizable flag is set
	long	fNumEntries;
	long	fKeyOffset;
	long	fKeySize;
	long	fKeyIsPtr;
	long	ref_count;
	const char 	*table_name;
	ItemExtractor item_extractor_callback;

#ifdef CONFIG_USE_OPTIK_LOCK
	optik_t hashtable_lock;
#else
	pthread_rwlock_t hashtable_rwlock;
#endif
	int flag_locking:1,
			flag_resizable:1;
} HashTable;

#define KEY_SIZE_ZERO 0
#define HASH_ITEM_IS_PTR_TYPE 1
#define HASH_ITEM_NOT_PTR_TYPE 0
#define HASHTABLE_NAME(x)	(x->table_name)
#define HASHTABLE_MAXSIZE(x)	(x)->max_size
#define HASHTABLE_SIZE(x)	(x->fTableSize)
#define HASHTABLE_ENTRIES(x)	(x->fNumEntries)
#define HASHTABLE_ITEM_EXTRACTOR_CALLBACK(x)	(x->item_extractor_callback)
#define HASHTABLE_LOCK(x)	(x->hashtable_rwlock)
#define HASHTABLE_KEYSIZE(x)	(x->fKeySize)
#define HASHTABLE_KEYOFFSET(x)	(x->fKeyOffset)
#define HASTABLE_ISTABLELOCKING(x)	(x->flag_locking)
#define HASTABLE_ISTABLERESIZABLE(x)	((x)->flag_resizable==1)
#define HASHTABLE_ISKEYPTR(x)	(x->fKeyIsPtr)
#define HASHTABLE_DATA(x)	(x->fTable)

#define HASHTABLE_SETFLAG(x, y)	(x)->y=1
#define HASHTABLE_CLEARFLAG(x, y)	(x)->y=0

#define HASHTABLE_EXTRACT_ITEM(x, y) ((*x->item_extractor_callback)(y))

typedef void *(*evictor_callback)(ContextData *);

HashTable *HashTableInstantiate(HashTable *, int offset, int size, long isPtr, const char *, ItemExtractor item_extractor_callback);
HashTable* HashTableLockingInstantiate(HashTable *ht_ptr_in, int offset, int size, long isPtr, const char *, ItemExtractor item_extractor_callback);
void ReleaseHash(HashTable* hash);

void *AddToHash(HashTable* hash, void* item);
void *AddToHashWithReference (HashTable *hash, void *item, void(*reference_incrementer_callback)(RecyclerClientData *, int));
void *AddToHashEvictIfNecessary (HashTable *hasht_ptr, const void *item_key, void *item_container_ptr, evictor_callback, ContextData *, void **);
void *AddToHashEvictIfNecessaryWithReference (HashTable *hasht_ptr,  const void *item_key, void *item_container_ptr, void *(*item_evictor_callback)(), void **, void(*reference_incrementer_callback)(RecyclerClientData *, int), void(*reference_decrementer_callback)(RecyclerClientData *, int));
void *HashLookup(HashTable* hash, void* data, bool);
void *HashLookupWithReference(HashTable *hash, const void *item_key, void(*reference_incrementer_callback)(RecyclerClientData *, int));
void *RemoveFromHash(HashTable *hash, void *item_container);
void *RemoveFromHashWithReference(HashTable *hash, void *item_value_ptr, void(*reference_decrementer_callback)(RecyclerClientData *, int));

void MergeHashEntries(HashTable* destination, HashTable* source);
int GetHashEntries(HashTable* hash, void** itemArray, long itemArraySize);


int HashTable_RdLock (HashTable *ht_ptr, int);
int HashTable_WrLock (HashTable *ht_ptr, int);
int HashTable_UnLock (HashTable *ht_ptr);

#endif /* SRC_INCLUDE_HASH_H_ */
