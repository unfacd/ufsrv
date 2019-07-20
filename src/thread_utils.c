/*
 * thread_utils.c
 *
 *  Created on: 29Nov.,2017
 *      Author: ayman
 */


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <assert.h>
#include <thread_utils.h>

int
PutIntoLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr)
{
	if (IsObjectInLockedObjectsStore(ht_ptr, obj_ptr))	return 0;

	if ((hopscotch_insert_configurable(ht_ptr, (uint8_t *)obj_ptr))==0)	return 0;

	return_error:
	return -1;

}


int
RemoveFromLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr)
{

	if (!IsObjectInLockedObjectsStore(ht_ptr, obj_ptr))	goto return_error;

	void *obj_ptr_removed;
	if (IS_PRESENT((obj_ptr_removed=hopscotch_remove_configurable(ht_ptr, obj_ptr))))
	{
		assert(obj_ptr_removed==obj_ptr);
		return 0;
	}

	return_error:
	return -1;

}

