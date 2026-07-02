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

#include "include/standard_lua_includes.h"
#include "include/nportredird.h"
#include "uflib/standard_valgrind_includes.h"

#include "jobworkers_utils.h"
#include "jobworkers/base_thread_context_data_type.h"
#include "jobworkers/worker_ufsrv_thread.h"

extern ufsrv *const masterptr;

static void _InitialiseJobWorkersPoolSignalling(WorkersConfigDescriptor *jobworkers_pool_descriptor);

size_t
GetJobWorkersPoolSize(size_t default_sz)
{
  size_t pool_size = default_sz;

  lua_getglobal(masterptr->lua_ptr, "ufsrv_workers_thread_pool");
  if (!lua_isnumber(masterptr->lua_ptr, -1)) {
    syslog(LOG_ERR, "LaunchUfServerWorkerThreads: ERROR: UNRECOGNISED VALUE SET FOR 'ufsrv_workers_thread_pool': using default '%d'", _CONFIGDEFAULT_MAX_UFSRV_WORKERS);
  } else	pool_size = (int)lua_tonumber(masterptr->lua_ptr, -1);

  if (pool_size < 1) pool_size = default_sz;

  return pool_size;
}

/**
 * @brief Convenient grouping of initialisers for the worker pool
 * @param pool_descriptor Per-instance pool descriptor to be initialised
 * @return
 */
UFSRVResult *
DefaultUfsrvWorkerPoolOneoffInitialiser(WorkerPoolDescriptor *pool_descriptor)
{
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.ufsrv_http_request_context_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.ufsrv_instrumentation_backend_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.ufsrv_db_backend_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.worker_persistance_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.worker_usrmsg_cachebackend_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.worker_fence_cachebackend_key), NULL);
  pthread_key_create(&(pool_descriptor->workers_pool_config_descriptor.ufsrv_msgqueue_pub_key), NULL);

  return NULL;
}

#if 0//def CONFIG_USE_LOCKLESS_UFSRV_WORKERS_QUEUE

static void
SpawnUfServerWorkers (SessionsDelegator *sd_ptr)
{
	extern void *ThreadUFServerWorker (void *);
	int pool_size=3;

	lua_getglobal(masterptr->lua_ptr, "ufsrv_workers_thread_pool");
	if (!lua_isnumber(masterptr->lua_ptr, -1))
	{
		syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED VALUE SET FOR 'ufsrv_workers_thread_pool': using default '%d'", __func__, _CONFIGDEFAULT_MAX_UFSRV_WORKERS);
	}
	else	pool_size=(int)lua_tonumber(masterptr->lua_ptr, -1);

	if (pool_size<1) pool_size=_CONFIGDEFAULT_MAX_UFSRV_WORKERS;

	sd_ptr->jobworkers.workers=malloc(sizeof(pthread_t)*pool_size);

	//allocate one whole continuous chunk for all threads, include queue storage
	sd_ptr->jobworkers.ufsrv_work_queues=calloc(pool_size, sizeof(LocklessSpscQueue)+(CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE*sizeof(QueueClientData *)));
	void *allocation_tracker=sd_ptr->jobworkers.ufsrv_work_queues;

	int i;
	int result;
	for (i=0; i!=pool_size; i++)
	{
		LocklessSpscQueue *lockless_queue=allocation_tracker;
		QueueClientData 	**queue_storage=allocation_tracker+sizeof(LocklessSpscQueue);
		LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE);
		allocation_tracker+=(sizeof(LocklessSpscQueue)+(sizeof(QueueClientData *)*CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE));

		result=pthread_create( &(sd_ptr->jobworkers.workers[i]), NULL, ThreadUFServerWorker, (void *)lockless_queue);
		if (result!=0)
		{
			syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, pool_size, i);
			exit (-1);
		}
	 }//for

	syslog(LOG_INFO, "%s (queues:'%p': SUCCESSFULLY spawned '%d' UFServer Worker Threads...", __func__, sd_ptr->jobworkers.ufsrv_work_queues, pool_size);

}

#else

/**
 * @brief Utility function to help standardise the instantiation of Ufsrv JobWorker threads pool. There is no overarching delegator for these threads;
 * instead, users raise condition variables directly, which worker threads respond to, depending on their availability. Each instantiated worker thread is
 * provided with its own instance of initialised BaseThreadContextData.
 * @param pool_descriptor Specifications for the jobworkers thread pool, including condition variables.
 * @param user_thread_ctx_allocation_sz  User-managed thread data context allocated on behalf of user. Must be  > 0, otherwise
 * it is ignored and not initialised.
 */
void __attribute__((nonnull(1)))
LaunchUfServerWorkerThreads(WorkerPoolDescriptor *pool_descriptor, size_t user_thread_ctx_allocation_sz)
{
  size_t pool_size = pool_descriptor->workers_pool_config_descriptor.pool_sz;

  _InitialiseJobWorkersPoolSignalling(&pool_descriptor->workers_pool_config_descriptor);

  //standard memory pool for pthread data type divided amongst all threads
  pool_descriptor->workers_pool_config_descriptor.workers = malloc(sizeof(pthread_t) * pool_size);

#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(pool_descriptor->workers_pool_config_descriptor.workers, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(pool_descriptor->workers_pool_config_descriptor.workers, sizeof(pthread_t) * pool_size);
#endif

  //standard memory pool for BaseThreadContextData divided amongst all threads
  BaseThreadContext  *mempool_base_thread_context = calloc(pool_size, sizeof(BaseThreadContext));
#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(mempool_base_thread_context, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(mempool_base_thread_context, sizeof(BaseThreadContext) * pool_size);
#endif

  //standard memory pool for user-provided thread data context. Opaque to this interface.
  ThreadContextData *mempool_user_thread_context = NULL;
  if (user_thread_ctx_allocation_sz > 0) {
    mempool_user_thread_context = calloc(pool_size, user_thread_ctx_allocation_sz);
#if __VALGRIND_DRD
    VALGRIND_CREATE_MEMPOOL(mempool_user_thread_context, 0, 1);
    VALGRIND_MAKE_MEM_NOACCESS(mempool_user_thread_context, user_thread_ctx_allocation_sz * pool_size);
#endif
  }

  int i;
  int result;
  BaseThreadContext  *base_thread_ctx;

  for (i=0; i != pool_size; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(pool_descriptor->workers_pool_config_descriptor.workers, &(pool_descriptor->workers_pool_config_descriptor.workers[i]), sizeof(pthread_t));
    VALGRIND_MEMPOOL_ALLOC(mempool_base_thread_context, &(mempool_base_thread_context[i]), sizeof(BaseThreadContext));
#endif

    base_thread_ctx = &(mempool_base_thread_context[i]);
    base_thread_ctx->thread_idx = i;
    base_thread_ctx->pool_descriptor = pool_descriptor;
    if (user_thread_ctx_allocation_sz > 0) {
#if __VALGRIND_DRD
      VALGRIND_MEMPOOL_ALLOC(mempool_user_thread_context, (char *)mempool_user_thread_context + (i * user_thread_ctx_allocation_sz), user_thread_ctx_allocation_sz);
#endif
      base_thread_ctx->user_thread_context = (ThreadContextData *)(((char *)mempool_user_thread_context) + (i * user_thread_ctx_allocation_sz));
    }

    result = pthread_create(&(pool_descriptor->workers_pool_config_descriptor.workers[i]), NULL, GetUfsrvWorkerThreadHandler(), (void *)base_thread_ctx);
    if (result != 0) {
      syslog(LOG_ERR, "LaunchUfServerWorkerThreads: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%lu', iteration: '%d'): terminating...", pool_size, i);
      exit (-1);
    }
  }//for

  syslog(LOG_INFO, "LaunchUfServerWorkerThreads: SUCCESSFULLY spawned '%lu' UFServer Worker Threads...", pool_size);
}

#endif

static void __attribute__((nonnull(1)))
_InitialiseJobWorkersPoolSignalling(WorkersConfigDescriptor *jobworkers_pool_descriptor)
{
  //mutexes and cond vars for Events Work Queue
  //TODO: we are still using the old mutex/cond variables. should migrate to this struct
  int result;
  pthread_mutexattr_init(&jobworkers_pool_descriptor->work_queue_mutex_attr);
  pthread_mutexattr_settype(&jobworkers_pool_descriptor->work_queue_mutex_attr,  PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);
  pthread_mutex_init(&jobworkers_pool_descriptor->work_queue_mutex, &jobworkers_pool_descriptor->work_queue_mutex_attr);

  pthread_cond_init(&jobworkers_pool_descriptor->queue_not_empty_cond, NULL);
  result = pthread_cond_init(&jobworkers_pool_descriptor->queue_empty_cond, NULL);
  //result = pthread_cond_init(&sd_ptr->queue_not_full_cond, NULL);

  if (result != 0) {
    char error_str[MEDIUMBUF] = {0};
    strerror_r(errno, error_str, MEDIUMBUF);
    syslog(LOG_ERR, "%s: UFServerWorkers Pool: TERMINATING (errno: '%d'): COULD NOT INITIALISE mutex and cond vars: error: '%s'...",
           __func__ , errno, error_str);

    exit(-1);
  }

  syslog(LOG_INFO, ">> %s: UFServerWorkers Pool: SUCCESSFULLY Initialised mutex and cond vars.. ", __func__ );
}