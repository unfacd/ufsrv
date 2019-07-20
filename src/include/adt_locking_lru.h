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

#ifndef SRC_INCLUDE_ADT_LOCKING_LRU_H_
#define SRC_INCLUDE_ADT_LOCKING_LRU_H_


#include <hashtable.h>
#include <instance_type.h>
#include <adt_locking_lru_type.h>

typedef void (*hashtable_init_callback)(HashTable *, size_t, unsigned long);
typedef void InstanceHolderForLruItem;

#define LOCKINGLRU_EXTRACT_ITEM(x, y) ((*x->item_extractor_callback)(y))
#define LOCKINGLRU_PRINT_ITEM(x, y, z) ((*x->item_printer_callback)(y, z))

LockingLru *InitLockingLru (LockingLru *lru_ptr_in, const char *lru_name, size_t, HashTable *hash_table_ptr, hashtable_init_callback, ItemExtractor, ItemPrinter);
LruClientData *LockingLruSet (LockingLru *lru_ptr, Session *sesn_ptr, LruClientData *client_data_ptr);
LruClientData *LockingLruGet (LockingLru *lru_ptr, Session *sesn_ptr, const void *, LruClientData **client_data_ptr_evicted);
LockingLru *LockingLruAddToFront (LockingLru *lru_ptr, LruClientData *data, LockingLruItem *lru_item_in, bool flag_lock);
LockingLru *LockingLruAddToRear (LockingLru *lru_ptr, LruClientData *data, LockingLruItem *lru_item_in, bool flag_lock);
LruClientData *LockingLruRemoveFromFront (LockingLru *lru_ptr, bool flag_lock);
LruClientData *LockingLruRemoveFromRear (LockingLru *lru_ptr, bool flag_lock);
LruClientData *LockingLruRemoveThis (LockingLru *lru_ptr, LruClientData *client_data_ptr, bool flag_lock);
size_t LockingLruSize (LockingLru *lru_ptr);
size_t LockingLruDescribeItems (LockingLru *lru_ptr, bool flag_lock);
LruClientData * LockingLruPromote (LockingLru *lru_ptr, Session *, const void *item_key, LruClientData *client_data_ptr);
bool LockingLruRearItemCheck (LockingLru *lru_ptr, LruClientData *client_data_ptr, ContextData *, void(*lrucache_headitemcheck_callback) (LruClientData *, bool));
LruClientData *LockingLruRearItemGet (LockingLru *lru_ptr);
LruClientData *LockingLruHeadItemGet (LockingLru *lru_ptr);

void InitLockingLruItemRecyclerTypePool ();
void LockingLruItemIncrementReference (InstanceHolderForLruItem *, int multiples);
void LockingLruItemDecrementReference (InstanceHolderForLruItem *, int multiples);
unsigned LockingLruItemPoolTypeNumber();
InstanceHolder *LockingLruItemGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);
void LockingLruItemReturnToRecycler (InstanceHolder *, ContextData *ctx_data_ptr, unsigned long call_flags);

void LockingLruLock (LockingLru *lru_ptr, void **lock_hook);
void LockingLruUnLock (LockingLru *lru_ptr, void *lock_hook);

#endif /* SRC_INCLUDE_ADT_LOCKING_LRU_H_ */
