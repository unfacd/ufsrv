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

#ifndef UFSRV_HASHTABLE_TYPE_H
#define UFSRV_HASHTABLE_TYPE_H

#include <stdlib.h>
#include <pthread.h>
#include <recycler/recycler_type.h>

#ifdef CONFIG_USE_OPTIK_LOCK
# include <cdt_optik_lock.h>
#endif

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

#endif //UFSRV_HASHTABLE_TYPE_H
