/*
 * thread_utils.h
 *
 *  Created on: 29Nov.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_THREAD_UTILS_H_
#define SRC_INCLUDE_THREAD_UTILS_H_

#include <adt_hopscotch_hashtable.h>

int PutIntoLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr);
int RemoveFromLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr);

static inline bool
IsObjectInLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr)
{

	return (hopscotch_lookup_configurable(ht_ptr, obj_ptr)!=NULL);
}


#endif /* SRC_INCLUDE_THREAD_UTILS_H_ */
