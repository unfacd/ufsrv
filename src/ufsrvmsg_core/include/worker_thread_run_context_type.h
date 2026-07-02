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

#ifndef UFSRV_WORKER_THREAD_RUN_CONTEXT_TYPE_H
#define UFSRV_WORKER_THREAD_RUN_CONTEXT_TYPE_H

#include <stddef.h>
#include <session_type.h>
#include <ufsrv_sessions_delegator_type.h>
#include <uflib/adt/adt_lamport_queue.h>
#include <jobworkers/base_thread_context_data_type.h>

typedef struct WorkerThreadRunContext {
//basic context data passed to worker threads at creation time
  size_t						        idx;
  InstanceHolderForSession  *ipc_pipe;
  LocklessSpscQueue         *queue;
  UfsrvSessionsDelegator    *sessions_delegator;
  LocklessMpscQueue         *msg_queue;
  BaseThreadContext         *base_thread_context;
  DrainBuffer               *drain_Buffer;
} WorkerThreadRunContext;

#endif //UFSRV_WORKER_THREAD_RUN_CONTEXT_TYPE_H
