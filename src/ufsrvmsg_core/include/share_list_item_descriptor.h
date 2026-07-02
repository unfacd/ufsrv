/**
 * Copyright (C) 2015-2022 unfacd works
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


#ifndef UFSRV_SHARE_LIST_ITEM_DESCRIPTOR_H
#define UFSRV_SHARE_LIST_ITEM_DESCRIPTOR_H

#include <stdint.h>
#include <uflib/adt/adt_hopscotch_hashtable.h>

//Convenient type to simplify the logic share lists processing for stored items and generalising their utility
typedef struct ShareListItemDescriptor {
  size_t        size; //size of key
  size_t        key_offset; //if key is located inside a host struct, provide offset to it
  ItemExtractor extractor_callback; //optional user-defined callback to layer back stored object (to identify its key offset)
} ShareListItemDescriptor;

typedef struct ShareListItemKeyStoreValue {
  unsigned long key_value;  //Value to read hash from
  uintptr_t     store_value; //stored item associated with key
  ShareListItemDescriptor *item_descriptor;
} ShareListItemKeyStoreValue;

#endif //UFSRV_SHARE_LIST_ITEM_DESCRIPTOR_H
