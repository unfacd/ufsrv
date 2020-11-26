/*
 * adt_locking_lru_type.h
 *
 *  Created on: 16 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_ADT_LOCKING_LRU_TYPE_H_
#define SRC_INCLUDE_ADT_LOCKING_LRU_TYPE_H_


#include <hashtable.h>
#include <uflib/adt/adt_doubly_linkedlist.h>

#ifdef CONFIG_USE_ANDERSON_SPINLOCK
#include <cdt_anderson_spinlock.h>
#else
#include <pthread.h>
#endif

typedef void LruClientData;
typedef LruClientData * (*ItemExtractor)(LruClientData *);
typedef char * (*ItemPrinter)(LruClientData *, size_t );

typedef struct LockingLruItem {
		LruClientData 	*data;
		DoublyListNode	list_node;
} LockingLruItem;

typedef struct LockingLru {
	DoublyList			list;
	size_t					lru_size;//before we start evicting
	const char 			*lru_name;
	HashTable 			*hashtable;
  ItemExtractor   item_extractor_callback;
  ItemPrinter     item_printer_callback;

#ifdef CONFIG_USE_ANDERSON_SPINLOCK
	spinlock_anderson_t	spinlock_list;
#else
	pthread_spinlock_t spinlock_list;
#endif
} LockingLru;



#endif /* SRC_INCLUDE_ADT_LOCKING_LRU_TYPE_H_ */
