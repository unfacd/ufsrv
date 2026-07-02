/**
 * Copyright (C) 2015-2021 unfacd works
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

#ifndef UFSRV_COROUTINE_RUN_CONTEXT_TYPE_H
#define UFSRV_COROUTINE_RUN_CONTEXT_TYPE_H

#include <uflib/libaco/aco.h>
#include <session_type.h>

typedef struct CoroutineRunContext {
  aco_t *delegator; //main coroutine
  aco_share_stack_t *sstk; //peallocated share-stack
  InstanceHolderForSession *sesn_ptr_instance;
  ClientContextData *context_data;
} CoroutineRunContext;
#endif //UFSRV_COROUTINE_RUN_CONTEXT_TYPE_H
