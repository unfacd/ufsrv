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

#ifndef UFSRV_UFSRV_SESSIONS_DELEGATOR_TYPE_H
#define UFSRV_UFSRV_SESSIONS_DELEGATOR_TYPE_H

#include <session_type.h>
#include <uflib/recycler/instance_type.h>
#include <pthread.h>
#include <uflib/adt/adt_queue.h>
#include <uflib/adt/adt_hashtable.h>
#include <uflib/adt/adt_linkedlist.h>
#include <jobworkers/workers_config_descriptor_type.h>
#include <ufsrvmsg_core/msgqueue_backend/ufsrvmsgqueue_type.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <uflib/db/db_sql.h>
#include <uflib/adt/adt_lamport_queue.h>
#include <uflib/adt/adt_mpsc_queue_type.h>
#include <uflib/libaco/aco.h>

//Signalling buffer that needs to b drained (ie read from) regularly, as worker threads don't read its content
typedef struct DrainBuffer {
  size_t threshold_keeper;
} DrainBuffer;

typedef struct UfsrvSessionsDelegator {
  int epoll_handle;
  unsigned up_status;
  int maxfd;   /* highest file descriptor currently registered */

  //unauthenticated_idle=300, connected_idle=300, suspended_idle
  struct {
    unsigned  unauthenticated,
              connected,
              suspended,
              locationless;
  } user_timeouts;

  struct {
    HashTable hashtable;
  } hashed_sessions;

  struct {
    HashTable hashtable;
  } hashed_cookies;

  struct {
    HashTable hashtable;
  } hashed_userids;

  struct {
    HashTable hashtable;
  } hashed_usernames;

  struct {
    HashTable hashtable;
  } hashed_net_addresses;

  void *events_container; //epoll_event container memory initialised to max requested size upfront

  //for use by the delegator
  InstrumentationBackend 	  *instrumentation_backend_ptr; //used by non session worker threads
  UserMessageCacheBackend 	*usrmsg_cachebackend;
  FenceCacheBackend				  *fence_cachebackend;
  MessageQueueBackend 			*msgqueue_pub_ptr;//backend connection representing MessageQueue publisher not used by session workers.
  struct _h_connection 		  *db_backend_ptr;

  pthread_t session_delegator_thread;//Delegator thread one per ufserver

  WorkersConfigDescriptor *jobworkers_config_descriptor; //Each ufsrv instance can register a workers pool

#if 1
  //TODO: to be used for session i/o workers, currently split between npotrtredird.h and session_type.h
  //keys are initialised in UFSRVThreadsOnceInitialiser()
  struct {
    int setsize; //number of workers in the pool
    pthread_t *workers; //number of workers to spawn (as mem pool)

    //Assumes single shared queue for msg/work passing for all workers<->workder-delegator. Alt model uses dedicated Spsc queue per worker
    struct {
      pthread_cond_t  queue_not_empty_cond;
      pthread_cond_t  queue_empty_cond;
      pthread_mutex_t work_queue_mutex;//control the broadcasting of work availability for session workers
      pthread_mutexattr_t work_queue_mutex_attr;
      Queue queue;
    } work_queue;

    //todo phase out in favour of thread local
    pthread_key_t worker_persistance_key;//each thread gets its own instance of persistance object
    pthread_key_t	worker_usrmsg_cachebackend_key; //redis cachbackend
    pthread_key_t	worker_fence_cachebackend_key; //redis cachbackend
    pthread_key_t ufsrv_instrumentation_backend_key;//instrumentation
    pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue pub redis connection

    LocklessSpscQueue **work_queues;//work/msg passing queues: one queue per worker thread. Only delegator can write into it

    InstanceHolderForSession **to_session_worker_ipc;//Worker-Delegator->SessionWorker unidirectional pipe for signalling work
    DrainBuffer *drain_buffer_session_worker_ipc; //track how much written into the IPC pipe to ebale frequent flushing
    InstanceHolderForSession **to_worker_delegator_ipc;//SessionWorker->Worker-Delegator unidirectional pipe for fd re-arming requests

    //this should be replaced by lockless Mcsp queue from workers to worker-delegator
    pthread_mutex_t worker_delegator_ipc_queue_mutex;//store/retrieve session work requests
    Queue worker_delegator_ipc_queue; //this os worker->delegator request queue. Signalling via self-pipe
    pthread_key_t worker_delegator_pipe_key;//for threads to fetch their own pipe Session objects

    unsigned count_in_service;//how many are currently in service from the pool
    DrainBuffer drain_buffer;
  } session_workers_thread_pool;
#endif

  struct {
    int setsize; //number of workers in the pool
    pthread_t *workers; //number of workers to spawn (as mem pool)
    InstanceHolderForSession **to_worker_delegator_ipc; //Listener->Worker-Delegator unidirectional pipe for signalling connection events
    LocklessSpscQueue **work_queues;//one queue per listener thread with worker-delegator (to be phased out in favour of MpSC queue below)
    LocklessMpscQueue msg_queue; //multi-producer (listeners), single consumer (worker-delegator) msg passing queue
    DrainBuffer drain_buffer; //for worker-delegator to drain
  } connection_listeners_delegator;

  //  LocklessSpscQueue **sessions_work_queues;//one queue per worker thread

  //control the behaviour of producer SessionsDelegator and consumers i/O worker threads
  //to be migrated to session_worker_thread_pool above
  //  pthread_t *session_worker_ths;//workers spawned at once
  //  pthread_mutex_t work_queue_mutex;//This is the mutex that control the broadcasting of work availability for session workers
  //  pthread_mutexattr_t work_queue_mutex_attr;

  //queue/mutex not implemented yet, we read straight of the socket instead
  Queue worker_delegator_ipc_queue; //this os worker->delegator request queue signalling via self-pipe
  pthread_mutex_t worker_delegator_ipc_queue_mutex;//store/retrieve session work requests
  //InstanceHolderForSession **worker_delegator_ipc; //replaced above this the set of delegator-worker ipc pipe (currently self-pipe implementation
  //key initialise first in a global  Onceoff initialiser then each thread when starts does pthread_setspecific()
  pthread_key_t worker_delegator_pipe_key;

  //these are for delegator->worker work raising signals
  //  pthread_cond_t  queue_not_empty_cond;
  //  pthread_cond_t  queue_not_full_cond;
  //  pthread_cond_t  queue_empty_cond;
  //end migration

  InstanceHolderForSession *session_signal_fd;
  pid_t pid;
  struct {
    aco_t *delegator;
    aco_share_stack_t *sstk;
  } coroutines_context;
} UfsrvSessionsDelegator;

#endif //UFSRV_UFSRV_SESSIONS_DELEGATOR_TYPE_H
