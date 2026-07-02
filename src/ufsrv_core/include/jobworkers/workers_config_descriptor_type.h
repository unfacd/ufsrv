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

#ifndef UFSRV_WORKERS_CONFIG_DESCRIPTOR_TYPE_H
#define UFSRV_WORKERS_CONFIG_DESCRIPTOR_TYPE_H

#include <pthread.h>
#include "enum_jobworkers_pool_operating_state.h"
#include "uflib/adt/adt_queue.h"

typedef struct WorkersConfigDescriptor {
  enum JobWorkersPoolOperatingState up_status; //on/off state for the whole pool
  size_t pool_sz;
  pthread_t *workers; //number of workers to spawn
  pthread_cond_t  queue_not_empty_cond;
  pthread_cond_t  queue_empty_cond;
  pthread_mutex_t work_queue_mutex;
  pthread_mutexattr_t work_queue_mutex_attr;

  //todo these should be removed once thread_local implementation is complete
  pthread_key_t worker_persistance_key;//each thread gets its own instance of persistance object
  pthread_key_t	worker_usrmsg_cachebackend_key; //redis cachbackend
  pthread_key_t	worker_fence_cachebackend_key; //redis cachbackend
  pthread_key_t ufsrv_thread_context_key;//
  pthread_key_t ufsrv_http_request_context_key;//
  pthread_key_t ufsrv_instrumentation_backend_key;//instrumentation
  pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue publisher redis connection
  pthread_key_t ufsrv_db_backend_key;//ufsrv db backend access
  //

#if 0//def CONFIG_USE_LOCKLESS_UFSRV_WORKERS_QUEUE
  LocklessSpscQueue **ufsrv_work_queues;//one queue per worker thread
#else
  Queue ufsrv_work_queue;
#endif
  unsigned count_in_service;//how many are currently in service from the pool
} WorkersConfigDescriptor;

#endif //UFSRV_WORKERS_CONFIG_DESCRIPTOR_TYPE_H
