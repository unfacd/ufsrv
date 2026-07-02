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

/**
 * This is the main I/O event listener/dispatcher thread, delegating work to session based worker threads.
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <sys/epoll.h>
#include <sockets.h>
#include <uflib/scheduled_jobs/scheduled_jobs.h>
#include <uflib/utils_threads.h>
#include <misc.h>
#include <nportredird.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include "delegator_sfu_worker_thread.h"
#include <session_worker_sfu_thread.h>
#include <ufsrvwebsock/include/protocol_websocket_routines.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include "ufsrv_core/include/delegator_session_worker_thread.h"
#include <ufsrvmsg_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <jobworkers/ufsrvworker_pool_descriptor_type.h>
#include <jobworkers/base_thread_context_data_type.h>
#include <http_request.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <ufsrv_sessions_delegator_type.h>
#include <delegator_sfu_listener_thread.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <uflib/libaco/aco.h>
#include <coroutines/coroutine_run_context_provider.h>


static void *ThreadWorkerDelegator(void *);

static int RearmSessionInMonitoredWorkEvents(SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr) __attribute__((unused));

inline static void AddPipeConnectionToMonitoredEvents(UfsrvSessionsDelegator *);
static Session *DestructDelegatorWorkerInterConnectionPipe(SessionsDelegator *sd_ptr) __attribute__((unused));

static int _NotifySessionWorker(UfsrvSessionsDelegator *sd_ptr, QueueContextData *instance_sesn_ptr, int thread_idx);
static int _PushWorkReferenceToSessionWorker(LocklessSpscQueue *queue, QueueClientData *instance_sesn_ptr, int thread_idx);

static UfsrvSessionsDelegator sessions_delegator;

extern __thread ThreadContext ufsrv_thread_context;//allocation defined in original delegator: to be phased out eventually in favour of BaseThreadContext
__thread BaseThreadContext *base_thread_context;

static char *epoll_ctl_error_freeme (int error);
static UFSRVResult *_UfsrvWorkerThreadDataContextInitialiser(BaseThreadContext *thread_base_ctx_data);

extern ufsrv *const masterptr;

extern  const  Protocol *const protocols_registry_ptr;

int __attribute__((const))
GetWorkerDelegatorEventsHandler()
{
  return sessions_delegator.epoll_handle;
}

/**
 * @brief Launch the threading subsystem responsible for delegating I/O requests to workers.
 * @return
 */
int
LaunchSessionsSfuDelegatorThread(void)
{
  syslog(LOG_INFO, ">> %s: Creating Sessions Delegator thread...", __func__);
  pthread_create(&sessions_delegator.session_delegator_thread, NULL, ThreadWorkerDelegator, &sessions_delegator);

  return 1;

}

/**
 * @brief Callback initialiser for UfsrvWorker threads for ufsrvwebsock and ufsrvapi class servers. Used to initialise data
 * context for each worker thread (this is distinct from Session I/O worker threads).
 * @param thread_base_ctx_data Base Date context thread created by the worker delegator, forming the base of the data context
 * for each worker.
 */
__unused static UFSRVResult *
_UfsrvWorkerThreadDataContextInitialiser(BaseThreadContext *thread_base_ctx_data)
{
  ThreadContext *ufsrv_thread_context_ptr = thread_base_ctx_data->user_thread_context;
  WorkersConfigDescriptor *config_descriptor = &(thread_base_ctx_data->pool_descriptor->workers_pool_config_descriptor);

  //todo: this is the old pthread_key based implementation. Delete one the thread_local implementation is finalised.
  pthread_key_create(&(config_descriptor->ufsrv_thread_context_key), NULL);
  pthread_setspecific(config_descriptor->ufsrv_thread_context_key, (void *)&ufsrv_thread_context);

  HopscotchHashtableConfigurable  *locked_objects_store = &(thread_base_ctx_data->locked_objects_store);
  hopscotch_init_with_offset(&(locked_objects_store->hashtable), CONFIG_THREAD_LOCKED_OBJECTS_STORE_PFACTOR);
  locked_objects_store->keylen = 0;
  locked_objects_store->keylen = 64;
  locked_objects_store->hash_func = (uint64_t (*)(uint8_t *, size_t))inthash_u64;

  ufsrv_thread_context_ptr->ht_ptr = locked_objects_store;
  ufsrv_thread_context.ht_ptr = locked_objects_store;//TBD

  ufsrv_thread_context_ptr->res_ptr = &(thread_base_ctx_data->ufsrv_result);
  //  ufsrv_thread_context.res_ptr = &ufsrv_result;//TBD

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  if (IS_PRESENT(InitialiseHttpRequestContext(&(thread_base_ctx_data->http_request_context), 0))) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->ufsrv_http_request_context_key), NULL);
    pthread_setspecific(config_descriptor->ufsrv_http_request_context_key, (void *)&(thread_base_ctx_data->http_request_context));

    ufsrv_thread_context.http_request_context = &(thread_base_ctx_data->http_request_context);//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
    _exit(-1);
  }

  syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, &(thread_base_ctx_data->http_request_context), pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  InstrumentationBackend *instr_ptr = InstrumentationBackendInit(NULL, NULL);//no namespace
  if (instr_ptr) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->ufsrv_instrumentation_backend_key), NULL);//TODO: no clean up callback
    pthread_setspecific(config_descriptor->ufsrv_instrumentation_backend_key, (void *)instr_ptr);

    ufsrv_thread_context_ptr->instrumentation_backend = instr_ptr;
    ufsrv_thread_context.instrumentation_backend = instr_ptr;//TBD
  } else {
    syslog(LOG_NOTICE, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
  }

  syslog(LOG_INFO, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Ufsrv Worker thread: '%lu' (NOT IMPLEMENTED)...", __func__, instr_ptr, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  struct _h_connection *db_ptr = InitialiseDbBackend();
  if (db_ptr) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->ufsrv_db_backend_key), NULL);
    pthread_setspecific(config_descriptor->ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure

    ufsrv_thread_context_ptr->db_backend = db_ptr;
    ufsrv_thread_context.db_backend = db_ptr;//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
    _exit (-1);
  }

  syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  PersistanceBackend *per_ptr = InitialisePersistanceBackend(NULL);
  if (per_ptr) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->worker_persistance_key), NULL);
    pthread_setspecific(config_descriptor->worker_persistance_key, (void *)per_ptr);

    ufsrv_thread_context_ptr->persistance_backend = per_ptr;
    ufsrv_thread_context.persistance_backend = per_ptr;//TBD
  } else {
    syslog(LOG_ERR, "ThreadUFServerWorker: ERROR: COULD NOT INITIALISE Session Cache Backend for Ufsrv Worker thread: '%lu'...", pthread_self());
    exit (-1);
  }

  syslog(LOG_INFO, "%s: SUCCESS: Initialised Session Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  UserMessageCacheBackend *per_ptr_usrmsg = InitialiseCacheBackendUserMessage(NULL);
  if (per_ptr_usrmsg) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->worker_usrmsg_cachebackend_key), NULL);
    pthread_setspecific(config_descriptor->worker_usrmsg_cachebackend_key, (void *)per_ptr_usrmsg);

    ufsrv_thread_context_ptr->usrmsg_cachebackend = per_ptr_usrmsg;
    ufsrv_thread_context.usrmsg_cachebackend = per_ptr_usrmsg;//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
    _exit (-1);
  }

  syslog(LOG_INFO, "%s : SUCCESS: Initialised UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  FenceCacheBackend *per_ptr_fence = InitialiseCacheBackendFence(NULL);
  if (per_ptr_fence) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->worker_fence_cachebackend_key), NULL);
    pthread_setspecific(config_descriptor->worker_fence_cachebackend_key, (void *)per_ptr_fence);

    ufsrv_thread_context_ptr->fence_cachebackend = per_ptr_fence;
    ufsrv_thread_context.fence_cachebackend = per_ptr_fence;//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
    _exit (-1);
  }

  syslog(LOG_INFO, "%s : SUCCESS: Initialised Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  MessageQueueBackend *mq_ptr = BuildConnectionHandleForMessageQueueBackend(NULL);
  if (mq_ptr) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_key_create(&(config_descriptor->ufsrv_msgqueue_pub_key), NULL);
    pthread_setspecific(config_descriptor->ufsrv_msgqueue_pub_key, (void *)mq_ptr);

    ufsrv_thread_context_ptr->msgqueue_backend = mq_ptr;
    ufsrv_thread_context.msgqueue_backend = mq_ptr;//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for UfServerWorker thread: '%lu'...", __func__, pthread_self());
    exit (-1);
  }

  syslog(LOG_INFO, "%s: SUCCESS: Initialised MessageQueue Publisher Backend for UfServerWorker thread: '%lu'...", __func__, pthread_self());

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RECODE_NONE)
}

//Delegator controls the I/O worker threads through the work_queue
//work_queue is sourced from poll_events
//each worker deque and services the request based on Session referenced in the individual queue entries
//all worker threads block on cond work_queue->nEntries==0

UfsrvSessionsDelegator *
InitialiseWorkerDelegator(void)
{
  SetThreadName("ufWorkDelegatr");

  sessions_delegator.epoll_handle = epoll_create1(0);
  if (sessions_delegator.epoll_handle == -1) {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT CREATE EPOLL HANDLE: EXITING", __func__ );
    return NULL;
  }

  if (sessions_delegator.connection_listeners_delegator.setsize == 0) {
    sessions_delegator.connection_listeners_delegator.setsize = _CONFIGDEFAULT_MAX_LISTENER_WORKERS;
    syslog(LOG_ERR, "%s: Setting config option 'listener_workers_thread_pool' to default value of '%d' (this can be set in the config file)...", __func__ , sessions_delegator.connection_listeners_delegator.setsize);
  }
  sessions_delegator.events_container = malloc(sizeof(struct epoll_event) * sessions_delegator.session_workers_thread_pool.setsize);

  {
    //initialise aux instrumentation backend object for non-session worker use
    syslog(LOG_INFO, "InitialiseWorkerDelegator: Initialising Auxiliary Instrumentation Backend for Session Delegator thread");
    InstrumentationBackend *instr_ptr = InstrumentationBackendInit(NULL, NULL);//no namespace
    if (instr_ptr) {
      sessions_delegator.instrumentation_backend_ptr = instr_ptr;
    } else {
      syslog(LOG_INFO, "InitialiseWorkerDelegator: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Session Delegator thread");
      sessions_delegator.instrumentation_backend_ptr = NULL;
    }
  }

  {
    //initialise aux MessgeQueueBackend object for non-session worker use
    syslog(LOG_INFO, "%s: Initialising Auxiliary MessageQueue Backend for Session Delegator thread...", __func__);
    MessageQueueBackend *msgq_ptr = BuildConnectionHandleForMessageQueueBackend(NULL);
    if (msgq_ptr) {
      sessions_delegator.msgqueue_pub_ptr = msgq_ptr;
    } else {
      syslog(LOG_INFO, "%s: ERROR: COULD NOT INITIALISE Auxiliary MessageQueueBackend for Session Delegator thread", __func__);
      sessions_delegator.msgqueue_pub_ptr = NULL;
    }
  }

  sessions_delegator.up_status = 1;

  return &sessions_delegator;

}

void
RegisterJobWorkersConfigurationDescriptorForSfu(WorkersConfigDescriptor *workers_config_descriptor)
{
  sessions_delegator.jobworkers_config_descriptor = workers_config_descriptor;
}

void
SetWorkersThreadPoolSetsize(size_t setsize)
{
  sessions_delegator.session_workers_thread_pool.setsize = setsize;
}

void
SetListenerWorkersThreadPoolSetsize(size_t setsize)
{
  sessions_delegator.connection_listeners_delegator.setsize = setsize;
}

WorkersConfigDescriptor * __attribute__((const))
GetJobWorkersConfigurationDescriptorUfsrv()
{
  return sessions_delegator.jobworkers_config_descriptor;
}

static Session *
DestructDelegatorWorkerInterConnectionPipe(SessionsDelegator *sd_ptr)
{
  int i;
  Session *sesn_ptr_ipc = NULL;
  InstanceHolderForSession *instance_sesn_ptr_ipc;
  pthread_t *th_ptr = NULL;

  for (i=0; i!=sd_ptr->setsize; i++) {
    instance_sesn_ptr_ipc = sd_ptr->worker_delegator_ipc[i];
    //TODO: kill session
    sesn_ptr_ipc = SessionOffInstanceHolder(instance_sesn_ptr_ipc);
    free (sesn_ptr_ipc);
    free (instance_sesn_ptr_ipc);
    th_ptr = &(sd_ptr->session_worker_ths[i]);
    pthread_cancel(*th_ptr);
    //TODO: kill threas
  }//for

  return NULL;
}

size_t
UfsrvSfuGetSessionWorkersSize(void)
{
  return sessions_delegator.session_workers_thread_pool.setsize;
}

size_t __attribute__((const))
UfsrvGetConnectionListenerWorkersSize(void)
{
  return sessions_delegator.connection_listeners_delegator.setsize;
}

//#if 0//def CONFIG_USE_LOCKLESS_UFSRV_WORKERS_QUEUE
//
//static void
//SpawnUfServerWorkers (SessionsDelegator *sd_ptr)
//{
//	extern void *ThreadUFServerWorker (void *);
//	int pool_size=3;
//
//	lua_getglobal(masterptr->lua_ptr, "ufsrv_workers_thread_pool");
//	if (!lua_isnumber(masterptr->lua_ptr, -1))
//	{
//		syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED VALUE SET FOR 'ufsrv_workers_thread_pool': using default '%d'", __func__, _CONFIGDEFAULT_MAX_UFSRV_WORKERS);
//	}
//	else	pool_size=(int)lua_tonumber(masterptr->lua_ptr, -1);
//
//	if (pool_size<1) pool_size=_CONFIGDEFAULT_MAX_UFSRV_WORKERS;
//
//	sd_ptr->jobworkers.workers=malloc(sizeof(pthread_t)*pool_size);
//
//	//allocate one whole continuous chunk for all threads, include queue storage
//	sd_ptr->jobworkers.ufsrv_work_queues=calloc(pool_size, sizeof(LocklessSpscQueue)+(CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE*sizeof(QueueClientData *)));
//	void *allocation_tracker=sd_ptr->jobworkers.ufsrv_work_queues;
//
//	int i;
//	int result;
//	for (i=0; i!=pool_size; i++)
//	{
//		LocklessSpscQueue *lockless_queue=allocation_tracker;
//		QueueClientData 	**queue_storage=allocation_tracker+sizeof(LocklessSpscQueue);
//		LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE);
//		allocation_tracker+=(sizeof(LocklessSpscQueue)+(sizeof(QueueClientData *)*CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE));
//
//		result=pthread_create( &(sd_ptr->jobworkers.workers[i]), NULL, ThreadUFServerWorker, (void *)lockless_queue);
//		if (result!=0)
//		{
//			syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, pool_size, i);
//			exit (-1);
//		}
//	 }//for
//
//	syslog(LOG_INFO, "%s (queues:'%p': SUCCESSFULLY spawned '%d' UFServer Worker Threads...", __func__, sd_ptr->jobworkers.ufsrv_work_queues, pool_size);
//
//}
//
//#else
//
//#include <jobworkers/base_thread_context_data_type.h>
//#include <jobworkers/worker_ufsrv_thread.h>
//
///**
// * @brief Utility function to help standardise the instantiation of Ufsrv JobWorker threads pool. There is no overarching delegator for these threads;
// * instead client raise condition variables directly, which threads respond to, depending on availability. Each instantiated worker thread is
// * provided with its own instance of initialised BaseThreadContextData.
// * @param pool_descriptor Specifications for the jobworkers thread pool, including condition variables.
// * @param user_thread_ctx_allocation_sz  User-managed thread data context allocated on behalf of user. Must be  > 0, otherwise
// * it is ignored and not initialised.
// */
//void __attribute__((nonnull(1)))
//SpawnUfServerWorkers (WorkerPoolDescriptor *pool_descriptor, size_t user_thread_ctx_allocation_sz)
//{
//  size_t pool_size = pool_descriptor->workers_pool_config_descriptor.pool_sz;
//  SessionsDelegator *sd_ptr = pool_descriptor->sessions_delegator;
//
//  //standard memory pool for pthread data type divided amongst all threads
//  pool_descriptor->workers_pool_config_descriptor.workers = malloc(sizeof(pthread_t) * pool_size);
//
//#if __VALGRIND_DRD
//  VALGRIND_CREATE_MEMPOOL(pool_descriptor->workers_pool_config_descriptor.workers, 0, 1);
//  VALGRIND_MAKE_MEM_NOACCESS(pool_descriptor->workers_pool_config_descriptor.workers, sizeof(pthread_t) * pool_size);
//#endif
//
//  //standard memory pool for BaseThreadContextData divided amongst all threads
//  BaseThreadContextData  *mempool_base_thread_context = calloc(pool_size, sizeof(BaseThreadContextData));
//#if __VALGRIND_DRD
//  VALGRIND_CREATE_MEMPOOL(mempool_base_thread_context, 0, 1);
//  VALGRIND_MAKE_MEM_NOACCESS(mempool_base_thread_context, sizeof(BaseThreadContextData) * pool_size);
//#endif
//
//  //standard memory pool for user-provided thread data context. Opaque to this interface.
//  ThreadContextData *mempool_user_thread_context = NULL;
//  if (user_thread_ctx_allocation_sz > 0) {
//    mempool_user_thread_context = calloc(pool_size, user_thread_ctx_allocation_sz);
//#if __VALGRIND_DRD
//    VALGRIND_CREATE_MEMPOOL(mempool_user_thread_context, 0, 1);
//    VALGRIND_MAKE_MEM_NOACCESS(mempool_user_thread_context, user_thread_ctx_allocation_sz * pool_size);
//#endif
//  }
//
//  int i;
//  int result;
//  BaseThreadContextData  *base_thread_ctx;
//
//  for (i=0; i != pool_size; i++) {
//#if __VALGRIND_DRD
//    VALGRIND_MEMPOOL_ALLOC(pool_descriptor->workers_pool_config_descriptor.workers, &(pool_descriptor->workers_pool_config_descriptor.workers[i]), sizeof(pthread_t));
//    VALGRIND_MEMPOOL_ALLOC(mempool_base_thread_context, &(mempool_base_thread_context[i]), sizeof(BaseThreadContextData));
//#endif
//
//    base_thread_ctx = (BaseThreadContextData  *)&(mempool_base_thread_context[i]);
//    base_thread_ctx->thread_idx = i;
//    base_thread_ctx->pool_descriptor = pool_descriptor;
//    if (user_thread_ctx_allocation_sz > 0) {
//#if __VALGRIND_DRD
//      VALGRIND_MEMPOOL_ALLOC(mempool_user_thread_context, &(mempool_user_thread_context[i]), user_thread_ctx_allocation_sz);
//#endif
//      base_thread_ctx->thread_ctx_data = &(mempool_user_thread_context[i]);
//    }
//
//    result = pthread_create(&(pool_descriptor->workers_pool_config_descriptor.workers[i]), NULL, GetUfsrvWorkerThreadHandler, (void *)base_thread_ctx);
//    if (result != 0) {
//      syslog(LOG_ERR, "SpawnUfServerWorkers: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%d', iteration: '%d'): terminating...", pool_size, i);
//      exit (-1);
//    }
//  }//for
//
//  syslog(LOG_INFO, "SpawnUfServerWorkers: SUCCESSFULLY spawned '%d' UFServer Worker Threads...", pool_size);
//}
//
//#endif

/**
 *  Edge triggered: notification is on state of readiness event, not state of buffer ie whether it has has unread data in it or not. The latter is how level triggered works.
 *
 *  another way to put it:  transition from empty to non-empty for reads and from full to not-full for writes.
 *  Thus, to enable the next trigger, the buffers first have to be driven to empty on read/full on write (i.e. EAGAIN).
 *
 *  for listening sockets see http://stackoverflow.com/questions/14221339/epoll-wait-on-a-listener-socket-and-spurious-failures
 *
 */
int
EnableIoEventsNotification(int events_handle, InstanceHolderForSession *instance_sesn_ptr)
{
  struct epoll_event epoll_event = {0};
  epoll_event.events |= EPOLLIN;
  epoll_event.events |= EPOLLOUT;
  epoll_event.events |= EPOLLET;
  epoll_event.events |= EPOLLRDHUP;
  epoll_event.data.ptr = instance_sesn_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  if (epoll_ctl(events_handle, EPOLL_CTL_ADD, sesn_ptr->ssptr->sock, &epoll_event) == -1) {
    const char *error_str = epoll_ctl_error_freeme(errno);
    syslog (LOG_DEBUG, "%s {pid='%lu', epoll_fd:'%d', o:'%p'}: COULD NOT ADD (error: '%s') new event (fd='%d') to MonitoredEvents... (cid='%lu')", __func__, pthread_self(), events_handle, sesn_ptr, error_str, sesn_ptr->ssptr->sock, SESSION_ID(sesn_ptr));
    return 0;
  }

#ifdef __UF_FULLDEBUG
  syslog (LOG_DEBUG, "%s (pid:'%lu' o:'%p'): Adding new event (fd='%d') to MonitoredEvents... (cid='%lu')", __func__, pthread_self(), sesn_ptr, sesn_ptr->ssptr->sock, SESSION_ID(sesn_ptr));
#endif

  return 1;

}

static char *
epoll_ctl_error_freeme(int error)
{
  switch (error) {
    case EEXIST:
      return("'EEXIST' the supplied file descriptor fd is already registered with this epoll instance");
    case EBADF:
      return("'EBADF' error: invalid fd'");
    case EINVAL:
      return("'EINVAL' fd is the same a epfd, or the requested operation op is not supported by this interface'");
    case ENOENT:
      return("'ENOENT' 'fd is not registered with this epoll instance'");
    case ENOMEM:
      return("'ENOMEM' 'NOT ENOUGH MEMORY'");
    case ENOSPC:
      return("'ENOSPC' 'error: imit imposed by /proc/sys/fs/epoll/max_user_watches was encountered while trying to register'");
    default:
      return("ERROR NOT REGISTERED");
  }
}

__unused static int
RearmSessionInMonitoredWorkEvents(SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr)
{
  struct epoll_event epoll_event = {};
  epoll_event.events |= EPOLLIN;//|EPOLLONESHOT;
  epoll_event.events |= EPOLLET;
  epoll_event.events |= EPOLLRDHUP;
  epoll_event.events |= EPOLLONESHOT;
  epoll_event.data.u64 = 0;
  epoll_event.data.ptr = instance_sesn_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  if ((epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_MOD, sesn_ptr->ssptr->sock, &epoll_event)) == -1) {
    const char *error_str = epoll_ctl_error_freeme(errno);
    syslog (LOG_DEBUG, "%s (pid='%lu' o:'%p'): COULD NOT RE-ARM ONESHOT EVENT (error: '%s') new event (fd='%d') to MonitoredEvents... (cid='%lu')",
            __func__, pthread_self(), sesn_ptr, error_str, SESSION_SOCKETFD(sesn_ptr), SESSION_ID(sesn_ptr));
    return 0;
  }

  return 1;

}

__unused int
DisableIoEventsNotification(int events_handle, InstanceHolderForSession *instance_sesn_ptr)
{
  struct epoll_event epoll_event = {0};

  //epoll_event.events=0;//just to make sure it is resent to known state
  epoll_event.events |= EPOLLIN;
  epoll_event.events |= EPOLLOUT;
  epoll_event.data.u64 = 0;
  epoll_event.data.ptr = instance_sesn_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  if (epoll_ctl(events_handle, EPOLL_CTL_DEL, sesn_ptr->ssptr->sock, &epoll_event) == -1) {
#ifdef __UF_FULLDEBUG
    //can be fale positive, as fd can be automatically removed by the kernel
    const char *error_str=epoll_ctl_error_freeme(errno);
    syslog (LOG_INFO, "%s (pid:'%lu', o:'%p', cid:'%lu', socket_fd:'%d', error:'%s'): ERROR: COULD NOT REMOVE event from MonitoredEvents...)", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), error_str);
#endif
    return 0;//error
  }

#ifdef __UF_FULLDEBUG
  syslog (LOG_DEBUG, "%s (pid='%lu'): SUCCESSFULLY REMOVED event (fd='%d') from MonitoredEvents... (cid='%lu')", __func__, pthread_self(), sesn_ptr->ssptr->sock, sesn_ptr->session_id);
#endif

  return 1;

}

/**
 * This is older style implementation and assumes one listener only interfacing the delegator.
 * 	@brief: Add the IPC self-pipe between the Connection Listener -> Work Delegator. This signalling mechanism is used to fetch
 * 	new connections from New Connections Queue. Only the reader side of the pipe fd is plugged into epoll.
 * 	This should last fot the lifetime of the server.
 */
__unused inline static void
AddPipeConnectionToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr)
{
  if (masterptr->work_delegator_pipe) {
    struct epoll_event epoll_event = {};
    epoll_event.events = EPOLLIN|EPOLLET;
    epoll_event.data.u64 = 0;
    epoll_event.data.ptr = masterptr->work_delegator_pipe;

    Session *sesn_ptr_pipe = WORK_DELEGATOR_PIPE_SESSION;
    if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_ADD, sesn_ptr_pipe->dsptr->sock, &epoll_event) == -1) {//PIPE READER END
      syslog(LOG_ERR, "%s: COULD NOT add pipe connection to events loop: WILL NOT be able to process new connections: errno='%d'", __func__, errno);
    } else {
      syslog(LOG_ERR, "%s: SUCCESSFULLY added pipe connection to monitored events...", __func__);
    }
  } else {
    syslog(LOG_ERR, "%s: FATAL: masterptr->work_delegator_pipe is NOT SET: WILL NOT be able to process new connections", __func__);
  }

}

/**
 * @brief:	Having been signaled by epoll_wait read the socket associated with the Worker-Delegator Pipe (as raised by a worker thread)
 * and obtain a local reference to the 'Session *' that is to be re-queued for I/O processing by one of the Session workers.
 * This is the standard mechanism to to work around ET mode, whereby we get only one notification. The I/O loop semantics allow workers
 * to only read fixed block size per invocation. If there is more to be fetched, we won't know about that until epoll_wait  tells us
 * again, but that may never happen if the server stopped sending and there is unprocessed bytes in the kernel's buffers for a given socket.
 * We allow the workers to make that decision and raise a another I/O cycle, which may or may not yield bytes. This way one thread won't starve
 * other threads, because new requests go to the back of the queue.
 *
 * Socket is nonblocking.
 * TODO: In the future generalise this and use messaging queue (similar to one implemented Listener-Delegator which requires locking)
 * current implementation reads socket directly to fetch session id (perhaps consider use raw pointer value)
 *
 * At the moment t o there is no provision for priority queue.
 */
inline static InstanceHolderForSession *
WorkerDelegatorPipeGetSession(Session *sesn_ptr_ipc)
{
  InstanceHolderForSession *instance_sesn_ptr_target = NULL;

  //note we use dsptr
  ssize_t amount_read = read(sesn_ptr_ipc->dsptr->sock, (char *)&instance_sesn_ptr_target, sizeof(char *));
  int errno_this = errno;

  if (amount_read > 0 && amount_read == sizeof(char *)) {//hopefully we read 8 bytes
    syslog(LOG_ERR, LOGSTR_WDELEG_WORKERREAD_SUCCESS,  __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), SESSION_ID(SessionOffInstanceHolder(instance_sesn_ptr_target)), amount_read, LOGCODE_WDELEG_WORKERREAD_SUCCESS);

    SessionDecrementReference(instance_sesn_ptr_target, 1);

    return instance_sesn_ptr_target;
  } else {//fleshed out for extra diagnostics
    if (amount_read == 0) {
      goto exit_pipe_issues;
    } else {
      if (errno_this == EAGAIN || errno_this == EWOULDBLOCK) {
        //blocking
        goto exit_pipe_issues;
      } else {
        //error
        exit_pipe_issues:
        syslog(LOG_ERR, LOGSTR_WDELEG_WORKERREAD_ERR, __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), errno_this, amount_read, LOGCODE_WDELEG_WORKERREAD_ERR);
      }
    }
  }

  return NULL;

}

/**
 * 	@brief: This keeps track of how many notifications have been written through the IPC socket. Since these notifications
 * 	are used for signalling, the data written to fd (to cause the socket to be polled) is never read, so after awhile the fd's
 * 	incoming buffer will reach capacity and won't be able to be used, so we "drain" it by reading the socket's inbuffer.
 * 	The recipient of the notification must call this every time an IPC socket is read for notification, which will cause a counter to increment.
 * 	Worker delegator gets notifications from the listener-delegators (or workers). But since it's only the delehgator that
 * 	reads these notifications, it is responsible for issuiing the drain.
 * 	SessionWorkers get notifications on their on IPC from Worker-Delegator, so they must issue that too, each worker keep track of it's
 * 	own drain buffer.
 *
 * 	Draining the pipe is necessary, because delegator-listener thread writes to it as a signalling mechanism, and not to transmit data.
 * 	Worker-threads on the other hand write session address, which in turn is read, therefore no draining is required in that case.
 */
size_t
NotificationPipeDrain(Session *sesn_ptr_ipc, UfsrvSessionsDelegator *sd_ptr, DrainBuffer *drain_buffer)
{
  static char scratch_drain_buffer[CONFIG_NEW_CONNECTIONS_PIPE_SIZE];

  statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.ipc_pipe_size", drain_buffer->threshold_keeper);

  //todo: disabled to force draining upon each invocation
//  if (++drain_buffer->threshold_keeper < CONFIG_NEW_CONNECTIONS_PIPE_DRAIN_THREASHOLD)	return 0;

  //note we use dsptr
  ssize_t amount_read = 0;
  amount_read = read(sesn_ptr_ipc->dsptr->sock, scratch_drain_buffer, CONFIG_NEW_CONNECTIONS_PIPE_SIZE);
  int errno_this = errno;

  if (amount_read > 0) {
#ifdef __UF_TESTING
    syslog(LOG_ERR, "%s {pid:'%lu', cid_pipe:'%lu', drainer_sz: '%lu', rc:'%lu'}: DRAINED PIPE", __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), drain_buffer->threshold_keeper, amount_read);
#endif
    if (amount_read > drain_buffer->threshold_keeper)	drain_buffer->threshold_keeper = amount_read;

    drain_buffer->threshold_keeper -= amount_read;

    return amount_read;
  } else {
    if (amount_read == 0) {
      goto exit_pipe_issues;
    } else {
      if (errno_this == EAGAIN || errno_this == EWOULDBLOCK) {
        //blocking
        goto exit_pipe_issues;
      } else {
        //error
        exit_pipe_issues:
        //syslog(LOG_ERR, LOGSTR_WDELEG_WORKERREAD_ERR, __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), errno_this, amount_read, LOGCODE_WDELEG_WORKERREAD_ERR);
        syslog(LOG_ERR, "%s {pid:'%lu', cid_pipe:'%lu', errno:'%d', rc:'%lu'}: ERROR NewConnectionsDelegatorPipe: COULD NOT READ PIPE", __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), errno_this, amount_read);
      }
    }
  }

  return amount_read;

}

/**
 * @brief Loop through all the incoming connections queues, polling for new connections and adding to monitored events set.
 * This is not used for UDP style servers, as 1) udp has no connection semantics, 2)incoming packets are deposited directly into Session's I/O MPSC queue
 * @param sd_ptr
 * @return Count of how many connections successfully added to monitored events set.
 */
__unused static size_t
_PollConnectionsListeners(UfsrvSessionsDelegator *sd_ptr)
{
  size_t processed = 0;
  int setsize = sd_ptr->connection_listeners_delegator.setsize;

  for (size_t i = 0; i <= setsize; i++) {
    QueueClientData 	*client_data_ptr;
    LocklessSpscQueue *queue = (LocklessSpscQueue *)sd_ptr->connection_listeners_delegator.work_queues + (i * sizeof(LocklessSpscQueue));

    while (LamportQueuePop(queue, &client_data_ptr)) {
      InstanceHolderForSession *instance_sesn_ptr_new = client_data_ptr;
      Session *sesn_ptr_new = SessionOffInstanceHolder(instance_sesn_ptr_new);

      sesn_ptr_new->when_serviced_end = time(NULL);//corresponding start time was set in AnswerTelnetRequest()

      if (EnableIoEventsNotification(GetWorkerDelegatorEventsHandler(), instance_sesn_ptr_new)) {
        processed++;
    #ifdef __UF_TESTING
        syslog(LOG_DEBUG, LOGSTR_WDELEG_NEWCONNECTION_ADDED, __func__, pthread_self(), client_data_ptr, SESSION_ID(sesn_ptr_new), LOGCODE_WDELEG_NEWCONNECTION_ADDED);
    #endif
      } else {
        syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', pid:'%lu'): ERROR: COULD NOT ADD new event... DROPPING PACKET and SUSPENDING into RECYCLER...", __func__, pthread_self(), sesn_ptr_new, SESSION_ID(sesn_ptr_new));
        close(sesn_ptr_new->ssptr->sock);
        SessionReturnToRecycler(instance_sesn_ptr_new, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);
      }
    }
  }

  return processed;
}

/**
 * @brief Worker-Delegator to Sessiion Worker signalling
 * @param sd_ptr
 * @param instance_sesn_ptr Session for which work is being requested
 * @param thread_idx thread index off the pool (stable id)
 * @return
 */
static int
_NotifySessionWorker(UfsrvSessionsDelegator *sd_ptr, QueueContextData *instance_sesn_ptr, int thread_idx)
{
  LocklessSpscQueue *queue = sd_ptr->session_workers_thread_pool.work_queues[thread_idx];
  Session *sesn_ptr_ipc = SessionOffInstanceHolder(sd_ptr->session_workers_thread_pool.to_session_worker_ipc[thread_idx]);
  if (_PushWorkReferenceToSessionWorker(queue, instance_sesn_ptr, thread_idx) == 0) {
    if (WriteIntoSessionWorkerIpcPipe(sesn_ptr_ipc) > 0) return 0;
  }

  return -1;
}

/**
 * @brief Worker-delegator adding a message to a given session worker's queue
 * @param queue Worker's queue
 * @param instance_sesn_ptr session reference to be messaged
 * @param thread_idx worker's fixed index in the worker's pool
 * @return
 */
static int
_PushWorkReferenceToSessionWorker(LocklessSpscQueue *queue, QueueClientData *instance_sesn_ptr, int thread_idx)
{
  if (LamportQueuePush(queue, (QueueClientData *)instance_sesn_ptr)) {
    syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKREQUEST_ADDED, __func__, pthread_self(), instance_sesn_ptr, 0UL, thread_idx, LamportQueueLeasedSize(queue), LOGCODE_WDELEG_WORKREQUEST_ADDED);

    return 0;
  } else {
    syslog(LOG_ERR, "%s (pid:'%lu', thread_idx:'%d'): ERRRO: QUEUE FULL FOR SESSION WORKER...", __func__, pthread_self(), thread_idx);
  }

  return 1;
}

#include <stun_agent/stun_agent.h>
#include <ufsrvmsg_core/type_providers/mpsc_queue_node_provider.h>

__unused static void
_LaunchSessionWorkerByCoroutine(UfsrvSessionsDelegator *sd_ptr, InstanceHolderForSession *sesn_ptr_instance)
{
  mpsc_queue_node *queue_node = mpsc_queue_pop(&sd_ptr->connection_listeners_delegator.msg_queue);
  if (IS_PRESENT(queue_node)) {
    InstanceHolderForCoroutineContext *coroutine_context_instance = GetCoroutineRunContext(REF_COUNTED(true));
    if (likely(IS_PRESENT(coroutine_context_instance))) {
      CoroutineRunContext *coroutine_context = CoroutineContextOffInstanceHolder(coroutine_context_instance);
      coroutine_context->delegator = sd_ptr->coroutines_context.delegator;
      coroutine_context->sstk = sd_ptr->coroutines_context.sstk;
      coroutine_context->sesn_ptr_instance = sesn_ptr_instance;
      coroutine_context->context_data = AS_CLIENT_CONTEXT_DATA(queue_node->context_data);
      aco_t* co = aco_create(sd_ptr->coroutines_context.delegator, sd_ptr->coroutines_context.sstk, 0, (aco_cofuncp_t)ContactStunServer, coroutine_context);
      aco_resume(co);
    }
  } else {
    syslog(LOG_ERR, "%s (pid:'%lu', sesn_instance:'%p'): ERRR: QUEUE RETURNED NULL NODE...", __func__, pthread_self(), sesn_ptr_instance);
  }
}

/** TODO incomplete implementation
 * @brief The main delegator event loop, delegating accepted incoming connections (through listeners) and fanning out work
 * to worker threads. All events are triggered by network sockets or file descriptors. The latter are used by connection
 * listeners.
 * delegator-listener --mpsc---> delegator-worker------>session
 * delegator-listener --mpsc--->^
 * Work parameters are passed through queues. Each worker has it's own SCSP queue with the delegator.
 * @param ptr
 * @return
 */
/*static void * __attribute__ (( no_sanitize_thread, nonnull(1) ))
ThreadWorkerDelegatorByCoroutine(void *ptr)
{
  UfsrvSessionsDelegator *sd_ptr = ptr;
  int setsize = sd_ptr->connection_listeners_delegator.setsize;

  unsigned 					connections_queue;
  unsigned long 		stat_atomic = 0L;
  QueueClientData 	*client_data_ptr;

  mpsc_queue_init(&sd_ptr->connection_listeners_delegator.msg_queue);
  _AddConnectionListenersPipeEndsToMonitoredEvents(sd_ptr);

  aco_thread_init(NULL);
  sd_ptr->coroutines_context.sstk = aco_share_stack_new(0);//used across worker coroutines
  sd_ptr->coroutines_context.delegator = aco_create(NULL, NULL, 0, NULL, NULL);

  //new connections queue processing block
  dequeue:
  connections_queue = 0;//reset state

#ifdef __UF_FULLDEBUG
  //syslog(LOG_DEBUG, "%s (pid='%lu' connection_queu_size:'%lu'): >> BEGIN DEQUEUE: NewConnectionsQueue...", __func__, pthread_self(), new_connections_queue_ptr->nEntries );
#endif

  long long timer_start = GetTimeNowInMicros();
  size_t processed = _PollConnectionsListeners(sd_ptr);
  long long timer_end = GetTimeNowInMicros();

  statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.dequeue.elapsed_time", timer_end-timer_start);
  //end of dequeue

  //main event listener
  while (1 != 2) {
    size_t 	broadcast_work;
    InstanceHolderForSession  *instance_sesn_ptr,
                              *instance_sesn_ptr_target;
    Session *sesn_ptr;

  #ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "ThreadWorkerDelegator: Blocking on I/O events: epoll_wait...");
  #endif

    broadcast_work = 0;

    //>>>>>>>>>>>>>>>>>>>>>>>>
    int ready_events_count = epoll_wait(sd_ptr->epoll_handle, sd_ptr->events_container, setsize, -1);
    //>>>>>>>>>>>>>>>>>>>>>>>>

    statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.queue_size", ready_events_count);

    if (ready_events_count > 0) {
      long long event_loop_start = GetTimeNowInMicros();

      for (unsigned j=0; j<ready_events_count; j++) {//read_ready_events
        struct epoll_event *ee_ptr;

        ee_ptr = sd_ptr->events_container + (j * sizeof(struct epoll_event));

        instance_sesn_ptr = (InstanceHolderForSession *)ee_ptr->data.ptr;

        if (IS_PRESENT(instance_sesn_ptr)) {
          sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
          sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers. This value can only be written into by this thread.
          if (sesn_ptr->ssptr->type == SOCK_PIPEWRITER) {//IPC pipe events (by worker threads) or new connections pipe event (by main listener)
            if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IPC)) {//delegator-worker ipc signalling. Not supported use case for this implementation
              instance_sesn_ptr_target = WorkerDelegatorPipeGetSession(sesn_ptr);
              if (IS_PRESENT(instance_sesn_ptr_target)) {
                if (_PushSessionReferenceToWorker(NULL*//*todo: GET worker thread's queue*//*, AS_QUEUE_CLIENT_DATA(instance_sesn_ptr_target), j % setsize) == 0)  broadcast_work++;
              } else {
                syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKER_NULLREQUEST, __func__, pthread_self(), SESSION_ID(sesn_ptr), LOGCODE_WDELEG_WORKER_NULLREQUEST);
                //back to loop
              }
            } else {
  #ifdef __UF_FULLDEBUG
              syslog(LOG_DEBUG, "%s (pid='%lu', j='%u'): NEW CONNECTION REQUEST Queue...", __func__, pthread_self(), j);
  #endif
              NewConnectionsPipeDrain(sesn_ptr, sd_ptr);//todo: this should be done for each pipe
              _LaunchSessionWorkerByCoroutine(sd_ptr, instance_sesn_ptr);
            }
          } else {//regular network i/o event
            int thread_idx = j % setsize;//round robin worker threads around each ready event
            if (_PushSessionReferenceToWorker(NULL*//*todo: GET worker thread's queue*//*, AS_QUEUE_CLIENT_DATA(instance_sesn_ptr), thread_idx) == 0)  broadcast_work++;
          }
        } else {
          syslog(LOG_ERR, "%s (pid='%lu' loop_counter='%u'): FATAL: sesen_ptr WAS NULL....", __func__, pthread_self(), j);
        }
      }//end read_ready_events

      if (broadcast_work > 0) {
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s (pid='%lu' broadcast_ready_sz:'%lu'): FINISHED Queueing jobs: SIGNALLING  on 'queue_not_empty_cond' and releasing mutex lock (-1)...", __func__, pthread_self(), broadcast_work);
  #endif
      } else {
        syslog(LOG_DEBUG, "%s (pid='%lu'): NO JOBS WERE QUEUED... Checking if received events contained New Connections requests", __func__, pthread_self());
      }

      long long event_loop_end = GetTimeNowInMicros();
      statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.elapsed_time", event_loop_end-event_loop_start);
    } else if (ready_events_count == -1) {
      if (errno == EINTR)	continue;

      {//TODO: eplo_wait recovery
        char *er;
        char erbuf[MBUF];
        er = strerror_r(errno, erbuf, MBUF);

        syslog(LOG_ERR, LOGSTR_WDELEG_EVENTS_POLLERROR, __func__, pthread_self(), errno, er, LOGCODE_WDELEG_EVENTS_POLLERROR);
      }
    }
  }

  return NULL;

}*/

#include <sys/types.h>
#include <signal.h>
#include <sys/signalfd.h>

static InstanceHolderForSession *_GenerateSignalFd(sigset_t *mask);
static int _AddSignalFdToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr);
static int _ProcessSignalEvent();

/**
 * @brief Setup the signal masking for the thread and return a signal fd that can be plugged int epoll.
 * @return
 */
static InstanceHolderForSession *
_GenerateSignalFd(sigset_t *mask)
{
  sigemptyset(mask);
  sigaddset(mask, SIGTERM);
  sigaddset(mask, SIGINT);
  int r = sigprocmask(SIG_BLOCK, mask, NULL);//block signal default action momentarily
  if (r == -1) {
    syslog(LOG_ERR, "%s (errno:'%d'): ERROR COULD NOT PROCESS SIGNAL MASK FOR THREAD", __func__ , errno);
    return NULL;
  }

  int sig_fd = 0;
  if ((sig_fd = signalfd(-1, mask, O_NONBLOCK)) < 0) {
    syslog(LOG_ERR, "%s (errno:'%d'): ERROR COULD NOT GENERATE SIGNAL FD", __func__ , errno);
    return NULL;
  }

  Socket 	*ss_ptr = calloc(1, (sizeof(Socket)));;
  Session	*sesn_ptr	=	NULL;

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, NULL, 0, -1))) {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise SIGNAL FD SESSION", __func__);
    free(ss_ptr);
    close(sig_fd);
    return NULL;
  }

  ss_ptr->type = SOCK_SIGNALFD; //written to by delegator
  ss_ptr->sock = sig_fd;
  strcpy(ss_ptr->address, "signal_fd.delegator.localhost");

  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);

  sessions_delegator.session_signal_fd = instance_sesn_ptr;

  return instance_sesn_ptr;
}

static int
_AddSignalFdToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr)
{
  struct epoll_event epoll_event = {0};
  epoll_event.events = EPOLLIN;
  epoll_event.data.ptr = sd_ptr->session_signal_fd;

  Session *session = SessionOffInstanceHolder(sd_ptr->session_signal_fd);

  if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_ADD, session->ssptr->sock, &epoll_event) == -1) {
    syslog(LOG_ERR, "%s {o:'%p', errno:'%d'}: COULD NOT ADD SIGNAL FD to events loop", __func__, session, errno);
    return -1;
  } else {
    syslog(LOG_ERR, "%s {o:'%p', fd:'%d'}: SignalFd: Added signal fd to monitored events...", __func__, session, session->ssptr->sock);
  }

  return 0;
}

static int
_ProcessSignalEvent()
{
  int signal_fd = SessionOffInstanceHolder(sessions_delegator.session_signal_fd)->ssptr->sock;
  struct signalfd_siginfo  siginfo;

  //more could be still in there. Rely on epoll level-triggering to push us back here
  ssize_t status = read(signal_fd, &siginfo, sizeof(siginfo));
  if(status != sizeof(siginfo)) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', errno:'%d', read_sz:'%ld'): ERROR COULD READ SIGNAL INFO", __func__, signal_fd, errno, status);
    return -1;
  }
  if (siginfo.ssi_signo == SIGINT) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED SIGINT SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
  } else if(siginfo.ssi_signo == SIGTERM) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED SIGTERM SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
  } else {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED UNMONITORED SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
    return siginfo.ssi_signo;
  }

  return 0;
}

static void * __attribute__ (( no_sanitize_thread ))
ThreadWorkerDelegator(void *ptr)
{
  sigset_t mask;
  UfsrvSessionsDelegator *sd_ptr = ptr;
  int setsize = sd_ptr->session_workers_thread_pool.setsize;

  mpsc_queue_init(&sd_ptr->connection_listeners_delegator.msg_queue);
  AddConnectionListenersPipeEndsToMonitoredEvents(sd_ptr);
  AddSessionWorkersPipeEndsToMonitoredEvents(sd_ptr);
  if (IS_PRESENT(_GenerateSignalFd(&mask))) _AddSignalFdToMonitoredEvents(sd_ptr);

  //main event listener
  while (1 != 2) {
  __unused size_t 	broadcast_work;
  InstanceHolderForSession *instance_sesn_ptr,
  *instance_sesn_ptr_target;
  Session *sesn_ptr;

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "ThreadWorkerDelegator: Blocking on I/O events: epoll_wait...");
#endif

  broadcast_work = 0;

  //>>>>>>>>>>>>>>>>>>>>>>>>
  int ready_events_count = epoll_pwait(sd_ptr->epoll_handle, sd_ptr->events_container, setsize, -1, &mask);
  //>>>>>>>>>>>>>>>>>>>>>>>>

  statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.queue_size", ready_events_count);

  if (ready_events_count > 0) {
    long long event_loop_start = GetTimeNowInMicros();

    for (unsigned j=0; j<ready_events_count; j++) {//read_ready_events
      struct epoll_event *ee_ptr;

      ee_ptr = sd_ptr->events_container + (j * sizeof(struct epoll_event));

      instance_sesn_ptr = (InstanceHolderForSession *)ee_ptr->data.ptr;

      if (IS_PRESENT(instance_sesn_ptr)) {
        sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
        sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers. This value can only be written into by this thread.
        if (sesn_ptr->ssptr->type == SOCK_PIPEWRITER) {//IPC pipe signalling events (by (session) worker threads) or new connections pipe event (by main listener)
          if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IPC)) {//delegator-worker ipc signalling. Push Session reference back to session worker
            instance_sesn_ptr_target = WorkerDelegatorPipeGetSession(sesn_ptr);
            if (IS_PRESENT(instance_sesn_ptr_target)) {
              int thread_idx = j % setsize;//round robin worker threads around each ready event
              if (_NotifySessionWorker(sd_ptr, AS_QUEUE_CLIENT_DATA(instance_sesn_ptr_target), thread_idx) == 0)  broadcast_work++;
            } else {
              syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKER_NULLREQUEST, __func__, pthread_self(), SESSION_ID(sesn_ptr), LOGCODE_WDELEG_WORKER_NULLREQUEST);
              //back to loop
            }
          } else if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTION_LISTENER)) {
  #ifdef __UF_FULLDEBUG
            syslog(LOG_DEBUG, "%s (pid='%lu', j='%u'): NEW CONNECTION REQUEST Queue...", __func__, pthread_self(), j);
  #endif
            //We don't read the pipe just drain whatever is there
            NotificationPipeDrain(sesn_ptr, sd_ptr, &sd_ptr->session_workers_thread_pool.drain_buffer);
            mpsc_queue_node *queue_node = mpsc_queue_pop(&sd_ptr->connection_listeners_delegator.msg_queue);
            if (IS_PRESENT(queue_node)) {
              int thread_idx = j % setsize;//round robin worker threads around each ready event
              if (_NotifySessionWorker(sd_ptr, AS_QUEUE_CONTEXT_DATA(queue_node->context_data), thread_idx) == 0) {
                ;
              }
              MpscQueueNodeReturnToRecycler(AS_INSTANCE_HOLDER(queue_node->finaliser.context_data)/*InstanceHolderFromClientContext(AS_CONTEXT_DATA(queue_node))*/, NO_CONTEXT_DATA, _DECREMENT_REFERENCE(true), CALLFLAGS_EMPTY);
            } else {
              syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: SPURIOUS LISTENER SIGNALLING: NO MSG FOUND IN QUEUE", __func__, pthread_self());
            }
          }
        } else if (sesn_ptr->ssptr->type == SOCK_SIGNALFD) {
          _ProcessSignalEvent();//unix signals
        } else {//regular network i/o event from directly connected socket
          int thread_idx = j % setsize;//round robin worker threads around each ready event
          if (_NotifySessionWorker(sd_ptr, AS_QUEUE_CLIENT_DATA(instance_sesn_ptr), thread_idx) == 0)  broadcast_work++;
        }
      } else {
        syslog(LOG_ERR, "%s (pid='%lu' loop_counter='%u'): FATAL: sesen_ptr WAS NULL....", __func__, pthread_self(), j);
      }
    }//end read_ready_events

    long long event_loop_end = GetTimeNowInMicros();
    statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.elapsed_time", event_loop_end-event_loop_start);
  } else if (ready_events_count == -1) {
    if (errno == EINTR)	continue;

    {//TODO: eplo_wait recovery
      char *er;
      char erbuf[MBUF];
      er = strerror_r(errno, erbuf, MBUF);

      syslog(LOG_ERR, LOGSTR_WDELEG_EVENTS_POLLERROR, __func__, pthread_self(), errno, er, LOGCODE_WDELEG_EVENTS_POLLERROR);
    }
  }
}

  return NULL;

}

//TBD just for reference
/*static void * __attribute__ (( no_sanitize_thread ))
ThreadWorkerDelegator (void *ptr)
{
  UfsrvSessionsDelegator *sd_ptr = ptr;
  int setsize = sd_ptr->session_workers_thread_pool.setsize;

  //this is uses conventional one listener
  LocklessSpscQueue *new_connections_queue_ptr = &(sd_ptr->new_connections.queue);

//  InitialiseDelegator(sd_ptr);

  unsigned 					connections_queue;
  unsigned long 		stat_atomic = 0L;
  QueueClientData 	*client_data_ptr;

  LocklessSpscQueue *session_workers_queues_idx[setsize];
  _AssignSessionWorkersQueues(sd_ptr->session_workers_thread_pool.sessions_work_queues, session_workers_queues_idx, setsize);

  AddPipeConnectionToMonitoredEvents(sd_ptr);
  AddAllWorkerDelegatorPipeConnectionsToMonitoredEvents(sd_ptr);

  //new connections queue processing block
  dequeue:
  connections_queue = 0;//reset state

#ifdef __UF_FULLDEBUG
//syslog(LOG_DEBUG, "%s (pid='%lu' connection_queu_size:'%lu'): >> BEGIN DEQUEUE: NewConnectionsQueue...", __func__, pthread_self(), new_connections_queue_ptr->nEntries );
#endif

  long long timer_start = GetTimeNowInMicros();

  //retrieve all new connection requests and add them to main event listener
  while (LamportQueuePop(new_connections_queue_ptr, &client_data_ptr)) {
    InstanceHolderForSession *instance_sesn_ptr_new = client_data_ptr;
    Session *sesn_ptr_new = SessionOffInstanceHolder(instance_sesn_ptr_new);

    sesn_ptr_new->when_serviced_end = time(NULL);//corresponding start time was set in AnswerTelnetRequest()

    if (AddWorkEvent(sd_ptr, instance_sesn_ptr_new)) {
  #ifdef __UF_TESTING
      syslog(LOG_DEBUG, LOGSTR_WDELEG_NEWCONNECTION_ADDED, __func__, pthread_self(), client_data_ptr, SESSION_ID(sesn_ptr_new), LOGCODE_WDELEG_NEWCONNECTION_ADDED);
  #endif
    } else {
      syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', pid:'%lu'): ERROR: COULD NOT ADD new event... DROPPING PACKET and SUSPENDING into RECYCLER...", __func__, pthread_self(), sesn_ptr_new, SESSION_ID(sesn_ptr_new));
      close(sesn_ptr_new->ssptr->sock);
      SessionReturnToRecycler(instance_sesn_ptr_new, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);
    }
  }

  long long timer_end = GetTimeNowInMicros();

  statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.dequeue.elapsed_time", timer_end-timer_start);
  //end of dequeue

  //main event listener
  while (1 != 2) {
  size_t 	broadcast_work;
  InstanceHolderForSession *instance_sesn_ptr,
  *instance_sesn_ptr_target;
  Session *sesn_ptr;

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "ThreadWorkerDelegator: Blocking on I/O events: epoll_wait...");
#endif

  broadcast_work = 0;

  //>>>>>>>>>>>>>>>>>>>>>>>>
  int ready_events_count = epoll_wait(sd_ptr->epoll_handle, sd_ptr->events_container, setsize, -1);
  //>>>>>>>>>>>>>>>>>>>>>>>>

  statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.queue_size", ready_events_count);

  if (ready_events_count > 0) {
    unsigned j;
    long long event_loop_start = GetTimeNowInMicros();

#ifdef __UF_FULLDEBUG
    syslog (LOG_DEBUG, "%s (pid='%lu' ready_events:'%d): --->>> epoll_wait returned: attempting to acquire Session Work Queue lock: I might block if other workers are fetching jobs...", __func__, pthread_self(), ready_events_count);
#endif

    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    if ((WorkQueueLock(sd_ptr, 0)) != 0) {
      //continue;
      //TODO: FIX RECOVERY...
    }
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#ifdef __UF_FULLDEBUG
syslog(LOG_DEBUG, "ThreadWorkerDelegator: SESSION WORK QUEUE MUTEX LOCK ACQUIRED (1)... looping through ready events... ");
#endif
    //read_ready_events
    for (j=0; j<ready_events_count; j++) {
      struct epoll_event *ee_ptr;

      ee_ptr = sd_ptr->events_container + (j * sizeof(struct epoll_event));

      instance_sesn_ptr = (InstanceHolderForSession *)ee_ptr->data.ptr;

      if (IS_PRESENT(instance_sesn_ptr)) {
        sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
        sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers. This value can only be written into by this thread.
        if (sesn_ptr->ssptr->type == SOCK_PIPEWRITER) {
          //IPC pipe events (by worker threads) or new connections pipe event (by main listener)
          if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IPC)) {
            //we have a lock on the Work Queue -> read off the Session reference and re-insert it into the queue
            instance_sesn_ptr_target = WorkerDelegatorPipeGetSession(sesn_ptr);
            if (IS_PRESENT(instance_sesn_ptr_target)) {
              //TODO: not sure I like this hackish implementation: separate into inlined function
              sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr_target);
              instance_sesn_ptr = instance_sesn_ptr_target; //set the context for the goto block
              goto __atomic_op;
            } else {
              syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKER_NULLREQUEST, __func__, pthread_self(), SESSION_ID(sesn_ptr), LOGCODE_WDELEG_WORKER_NULLREQUEST);
              //back to loop
            }
          } else {
#ifdef __UF_FULLDEBUG
            syslog(LOG_DEBUG, "%s (pid='%lu', j='%u'): NEW CONNECTION REQUEST Queue...", __func__, pthread_self(), j);
#endif
            NewConnectionsPipeDrain(sesn_ptr, sd_ptr);
            connections_queue = 1;
          }

          continue;//redundant
        } else {
          __atomic_op:
          //NOTE: Relaxed checking for connected connection status
          //            stat_atomic = __sync_add_and_fetch (&sesn_ptr->stat, 0);
          if (true) {// && SESNSTATUS_IS_SET(stat_atomic, SESNSTATUS_CONNECTED)) {
            int thread_idx = j % setsize;//round robin worker threads around each ready event
            if (LamportQueuePush(session_workers_queues_idx[thread_idx], (QueueClientData *)instance_sesn_ptr)) {
              syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKREQUEST_ADDED, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),j, LamportQueueLeasedSize(session_workers_queues_idx[thread_idx]), LOGCODE_WDELEG_WORKREQUEST_ADDED);

              broadcast_work++;
            } else {
              //queue full
              syslog(LOG_ERR, "%s (pid:'%lu', loop_counter:'%u', thread_idx:'%d'): ERRRO: QUEUE FULL FOR SESSION WORKER...", __func__, pthread_self(), j, thread_idx);
            }
          } else {
            //can happen a session was previously recycled, but we have some residual events in the queue, especially in level triggered mode
            syslog(LOG_NOTICE, LOGSTR_WDELEG_NONCONNECTED_REQUEST,	__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_WDELEG_NONCONNECTED_REQUEST);
          }
        }
      } else {
        syslog(LOG_ERR, "%s (pid='%lu' loop_counter='%u'): FATAL: sesen_ptr WAS NULL....", __func__, pthread_self(), j);
      }
    }
    //end read_ready_events

    if (broadcast_work > 0) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s (pid='%lu' broadcast_ready_sz:'%lu'): FINISHED Queueing jobs: SIGNALLING  on 'queue_not_empty_cond' and releasing mutex lock (-1)...", __func__, pthread_self(), broadcast_work);
#endif
      pthread_cond_broadcast(&sd_ptr->session_workers_thread_pool.work_queue.queue_not_empty_cond);
    } else {
      syslog(LOG_DEBUG, "%s (pid='%lu'): NO JOBS WERE QUEUED... Checking if received events contained New Connections requests", __func__, pthread_self());
    }

    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    //this will set off the other listeners
    if ((WorkQueueUnLock(sd_ptr)) != 0) {
      //todo error recovery
    }
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    long long event_loop_end = GetTimeNowInMicros();
    statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.elapsed_time", event_loop_end-event_loop_start);

    if (connections_queue) {
      //this gets penalised a bit as we process all other requests 1st
      //TODO: remove from epoll

#ifdef __UF_FULLDEBUG
syslog(LOG_DEBUG, "%s (pid:'%lu'): FOUND NEW EVENTS IN NEW CONNECTIONS QUEUE: FETCHING...",	__func__, pthread_self());
#endif

      goto dequeue; // NOLINT
    }
  } else if (ready_events_count == -1) {
    if (errno == EINTR)	continue;

    {//TODO: eplo_wait recovery
      char *er;
      char erbuf[MBUF];
      er = strerror_r(errno, erbuf, MBUF);

      syslog(LOG_ERR, LOGSTR_WDELEG_EVENTS_POLLERROR, __func__, pthread_self(), errno, er, LOGCODE_WDELEG_EVENTS_POLLERROR);
    }
  }
}

return NULL;

}*/

