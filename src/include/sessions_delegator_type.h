/*
 * sessions_delegator_type.h
 *
 *  Created on: 28 Jul 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SESSIONS_DELEGATOR_TYPE_H_
#define SRC_INCLUDE_SESSIONS_DELEGATOR_TYPE_H_

#include <session_type.h>
#include <instance_type.h>
#include <pthread.h>
#include <queue.h>
#include <hashtable.h>
#include <list.h>
#include <ufsrvmsgqueue_type.h>
#include <instrumentation_backend.h>
#include <db_sql.h>
#include <adt_lamport_queue.h>

enum  WorkerType {
	WORKERTYPE_SESSIONWORKER=1,
	WORKERTYPE_UFSRVWORKER
} ;

//basic context data passed to worker threads at creation time
typedef struct WorkerThreadCreationContext {
	size_t						        idx;
	InstanceHolderForSession  *ipc_pipe;
	LocklessSpscQueue         *queue;
} WorkerThreadCreationContext;

struct SessionsDelegator {
  int epoll_handle;
  unsigned up_status;
  int maxfd;   /* highest file descriptor currently registered */
  int setsize; /* max number of file descriptors tracked */

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

 //queue used between worker_delegator_thread and protocol_websocket_thread to register and fetch new connections requests
  struct {
#ifdef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
   LocklessSpscQueue queue;
#else
   Queue queue;
   pthread_mutex_t queue_mutex;
   pthread_mutexattr_t queue_mutex_attr;
#endif
 } new_connections;

  struct {
   Queue				queue;//sessions which have been previously suspended and never reclaimed within set timeout period
   pthread_rwlock_t 	queue_rwlock;
   pthread_t 			queue_manager_th;
   time_t 			queue_manager_last_run;	//last time the manager ran
 } recycled_sessions;

  void *events_container; //epoll_event container memory initialised to max requested size upfront

  //for use by the delegator
  InstrumentationBackend 	*instrumentation_backend_ptr; //used by non session worker threads
  UserMessageCacheBackend 	*usrmsg_cachebackend;
  FenceCacheBackend				*fence_cachebackend;
  MessageQueueBackend 			*msgqueue_pub_ptr;//backend connection representing MessageQueue publisher not used by session workers.
  struct _h_connection 		*db_backend_ptr;

  pthread_t session_delegator_thread;//Delegator thread one per ufserver

  pthread_attr_t th_attr;

  //set of variables that control the non-session service worker threads pool in ufsrv_worker_thread
  //makesure you initialise all keys in UFSRVThreadsOnceInitialiser (void);
  struct {
    pthread_t *workers; //number of workers to spawn
    pthread_cond_t  queue_not_empty_cond;
    pthread_cond_t  queue_empty_cond;
    pthread_mutex_t work_queue_mutex;
    pthread_mutexattr_t work_queue_mutex_attr;
    pthread_key_t worker_persistance_key;//each thread gets its own instance of persistance object
    pthread_key_t	worker_usrmsg_cachebackend_key; //redis cachbackend
    pthread_key_t	worker_fence_cachebackend_key; //redis cachbackend
    pthread_key_t ufsrv_thread_context_key;//
    pthread_key_t ufsrv_http_request_context_key;//
    pthread_key_t ufsrv_instrumentation_backend_key;//instrumentation
    pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue publisher redis connection
    pthread_key_t ufsrv_db_backend_key;//ufsrv db backend access
#if 0//def CONFIG_USE_LOCKLESS_UFSRV_WORKERS_QUEUE
    LocklessSpscQueue **ufsrv_work_queues;//one queue per worker thread
#else
    Queue ufsrv_work_queue;
#endif
    unsigned count_in_service;//how many are currently in service from the pool
  } ufsrv_thread_pool;

#if 0
  //TODO: to be used for session i/o workers, currently split between npotrtredird.h and session_type.h
  //keys are initialised in UFSRVThreadsOnceInitialiser()
  struct {
    pthread_t *workers; //number of workers to spawn
    Sessions *session_worker_ipc; //delegator-worker ipc pipe
    pthread_cond_t  queue_not_empty_cond;
    pthread_cond_t  queue_empty_cond;
    pthread_mutex_t work_queue_mutex;
    pthread_mutexattr_t work_queue_mutex_attr;
    pthread_mutex_t worker_delegator_ipc_queue_mutex;//store/retrieve session work requests
    pthread_key_t worker_persistance_key;//each thread gets its own instance of persistance object
    pthread_key_t	worker_usrmsg_cachebackend_key; //redis cachbackend
    pthread_key_t	worker_fence_cachebackend_key; //redis cachbackend
    pthread_key_t ufsrv_instrumentation_backend_key;//instrumentation
    pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue pub redis connection

    Queue work_queue;
    pthread_mutex_t worker_delegator_ipc_queue_mutex;//store/retrieve session work requests
    Queue worker_delegator_ipc_queue; //this os worker->delegator request queue signalling via self-pipe
    pthread_key_t worker_delegator_pipe_key;//for threads to fetch their own pipe Session objects

    unsigned count_in_service;//how many are currently in service from the pool
  } session_worker_thread_pool;
#endif

#ifdef CONFIG_USE_LOCKLESS_SESSION_WORKERS_QUEUE
  LocklessSpscQueue **sessions_work_queues;//one queue per worker thread
#else
  Queue sessions_work_queue; //this is delegator->worker job raising queue: signalling pthreadcond_wait
#endif

  //control the behaviour of producer SessionsDelegator and consumers i/O worker threads
  //to be migrated to session_worker_thread_pool above
  pthread_t *session_worker_ths;//workers spawned at once
  pthread_mutex_t work_queue_mutex;//store/retrieve session work requests
  pthread_mutexattr_t work_queue_mutex_attr;

  //queue/mutex not implemented yet, we read straight of the socket instead
  Queue worker_delegator_ipc_queue; //this os worker->delegator request queue signalling via self-pipe
  pthread_mutex_t worker_delegator_ipc_queue_mutex;//store/retrieve session work requests
  InstanceHolderForSession **worker_delegator_ipc; //this the set of delegator-worker ipc pipe (currently self-pipe implementation
  //key initialise first in a global  Onceoff initialiser then each thread when starts does pthread_setspecific()
  pthread_key_t worker_delegator_pipe_key;

  //these are for delegator->worker work raising signals
  pthread_cond_t  queue_not_empty_cond;
   pthread_cond_t  queue_not_full_cond;
   pthread_cond_t  queue_empty_cond;
   //end migration
  //pthread_cond_t work_queue_cond;
  pid_t pid;

};
typedef struct SessionsDelegator SessionsDelegator;

         //expects SessionDelegator *sessions_delegator_ptr
#define SESNDELEGATE_SESSIONCACHE(x)	&(x->hashed_sessions.hashtable)
#define SESNDELEGATE_USERIDCACHE(x)		&(x->hashed_userids.hashtable)
#define SESNDELEGATE_COOKIECACHE(x)		&(x->hashed_cookies.hashtable)
#define SESNDELEGATE_USERNAMECACHE(x)		&(x->hashed_usernames.hashtable)

#define THRKEY_WORKER_DELEGATOR_PIPE(x)	(x->worker_delegator_pipe_key)
#endif /* SRC_INCLUDE_SESSIONS_DELEGATOR_TYPE_H_ */
