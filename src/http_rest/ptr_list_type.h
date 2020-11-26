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

#ifndef UFSRV_PTR_LIST_TYPE_H
#define UFSRV_PTR_LIST_TYPE_H

struct onion_ptr_list_t{
  void *ptr;
  struct onion_ptr_list_t *next;
};
typedef struct onion_ptr_list_t onion_ptr_list;

#endif //UFSRV_PTR_LIST_TYPE_H
