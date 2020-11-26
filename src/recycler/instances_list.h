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


#ifndef UFSRV_INSTANCES_LIST_H
#define UFSRV_INSTANCES_LIST_H

#include <main_types.h>
#include <recycler/instance_type.h>
#include <recycler/instances_list_type.h>

ListItemInstance *AddtoInstancesList (InstancesList *ptr);
ListItemInstance *AddThisInstanceToList (InstancesList *lptr, ClientContextData  *usrptr);
ListItemInstance *AddThisMarshallerToList (InstancesList *lptr, MarshallerContextData marshaller);
int RemoveThisInstanceFromList (InstancesList *ptr, InstanceHolder *instance_holder_ptr);
int RemoveFromInstancesList (InstancesList *ptr, ListItemInstance *eptr);

inline static bool
IsInstanceListEmpty (const InstancesList *ptr)
{
  return (ILIST_SIZE(ptr) == 0);

}

#endif //UFSRV_INSTANCES_LIST_H
