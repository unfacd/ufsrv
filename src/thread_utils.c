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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <thread_utils.h>

int
PutIntoLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr)
{
	if (IsObjectInLockedObjectsStore(ht_ptr, obj_ptr))	return 0;

	if ((hopscotch_insert_configurable(ht_ptr, (uint8_t *)obj_ptr)) == 0)	return 0;

	return_error:
	return -1;

}

int
RemoveFromLockedObjectsStore (HopscotchHashtableConfigurable *ht_ptr, void *obj_ptr)
{

	if (!IsObjectInLockedObjectsStore(ht_ptr, obj_ptr))	goto return_error;

	void *obj_ptr_removed;
	if (IS_PRESENT((obj_ptr_removed = hopscotch_remove_configurable(ht_ptr, obj_ptr))))
	{
		assert(obj_ptr_removed == obj_ptr);
		return 0;
	}

	return_error:
	return -1;

}

