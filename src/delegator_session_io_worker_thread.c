/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <sys/epoll.h>
#include <sys/prctl.h>//for naming thread
#include <sockets.h>
#include <scheduled_jobs.h>
#include <adt_minheap.h>
#include <misc.h>
#include <redirection.h>
#include <nportredird.h>
#include <protocol.h>
#include <protocol_websocket.h>
#include <protocol_websocket_routines.h>
#include <instrumentation_backend.h>
#include <delegator_session_worker_thread.h>
#include <ufsrvmsgqueue.h>

static void *ThreadWorkerDelegator (void *);
static void SpawnIOSessionWorkers (SessionsDelegator *);
static int InitialiseDelegator (SessionsDelegator *);
static int AddWorkEvent (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr);
static int RemoveWorkEvent (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr);
static int RearmSessionInMonitoredWorkEvents (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr) __attribute__((unused));
static void SpawnUfServerWorkers (SessionsDelegator *sd_ptr);

#ifndef	CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
inline static int NewConnectionsQueueLock (int try_flag);
inline static int NewConnectionsQueueUnLock (void);
#endif

inline static void AddPipeConnectionToMonitoredEvents (SessionsDelegator *);
static Session *DestructDelegatorWorkerInterConnectionPipe (SessionsDelegator *sd_ptr) __attribute__((unused));
inline static void
AddAllWorkerDelegatorPipeConnectionsToMonitoredEvents (SessionsDelegator *sd_ptr);
static InstanceHolderForSession *InitDelegatorWorkerInterConnectionPipe (void);

static void _InitScheduledJobsStore (ScheduledJobs *scheduled_jobs, size_t count);

static SessionsDelegator sessions_delegator;
SessionsDelegator *const sessions_delegator_ptr=&sessions_delegator;

__thread/*thread_local*/ ThreadContext      ufsrv_thread_context; //one global multiplexed as local storage for each thread

static char *epoll_ctl_error_freeme (int error);

extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;

extern  const  Protocol *const protocols_registry_ptr;

int
CreateSessionsDelegatorThread (void)
{
	syslog(LOG_INFO, ">> %s: Creating Sessions Delegator thread...", __func__);
	pthread_create (&sessions_delegator_ptr->session_delegator_thread, NULL, ThreadWorkerDelegator, sessions_delegator_ptr);

	return 1;

}

//Delegator controls the I/O worker threads through the work_queue
//work_queue is sourced from poll_events
//each worker deque and services the request based on Session referenced in the individual queue entries
//all worker threads block on cond work_queue->nEntries==0

static int
InitialiseDelegator (SessionsDelegator *sd_ptr)
{
	sd_ptr->pid = pthread_self();

	sd_ptr->events_container = malloc(sizeof(struct epoll_event)*sd_ptr->setsize);
	sd_ptr->epoll_handle = epoll_create(sd_ptr->setsize);

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufWorkDelegatr", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	if (sd_ptr->epoll_handle == -1) {
		pthread_exit (NULL);
	}

	{//mutexes and cond vars
		//TOO: MIGRATE TO THE USE OF THE VARS defined below in ufsrv_thread_pool
		int result;
		pthread_mutexattr_init(&sd_ptr->work_queue_mutex_attr);
		pthread_mutexattr_settype(&sd_ptr->work_queue_mutex_attr,  PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);//Opportunistic "spinklock"
		result=pthread_mutex_init (&sd_ptr->work_queue_mutex, &sd_ptr->work_queue_mutex_attr);

		result=pthread_cond_init (&sd_ptr->queue_not_empty_cond, NULL);
		result=pthread_cond_init (&sd_ptr->queue_not_full_cond, NULL);
		result=pthread_cond_init (&sd_ptr->queue_empty_cond, NULL);

		if (result != 0) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_ERR, "InitialiseDelegator: TERMINATING (errno: '%d'): COULD NOT INITIALISE mutex and cond vars: error: '%s'...", errno, error_str);

			exit(-1);
		}

		syslog(LOG_INFO, ">> %s: SUCCESSFULLY Initialised mutex and cond vars", __func__);
	}

	{//mutexes and cond vars for Events Work Queue
		//TODO: we are still using the old mutex/cond variables. should migrate to this struct
		int result;
		pthread_mutexattr_init(&sd_ptr->ufsrv_thread_pool.work_queue_mutex_attr);
		pthread_mutexattr_settype(&sd_ptr->ufsrv_thread_pool.work_queue_mutex_attr,  PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);
		result=pthread_mutex_init (&sd_ptr->ufsrv_thread_pool.work_queue_mutex, &sd_ptr->ufsrv_thread_pool.work_queue_mutex_attr);

		result=pthread_cond_init (&sd_ptr->ufsrv_thread_pool.queue_not_empty_cond, NULL);
		result=pthread_cond_init (&sd_ptr->ufsrv_thread_pool.queue_empty_cond, NULL);
		//result=pthread_cond_init (&sd_ptr->queue_not_full_cond, NULL);

		if (result != 0) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_ERR, "InitialiseDelegator: UFServerWorkers Pool: TERMINATING (errno: '%d'): COULD NOT INITIALISE mutex and cond vars: error: '%s'...", errno, error_str);

			exit(-1);
		}

		syslog(LOG_INFO, ">> InitialiseDelegator: UFServerWorkers Pool: SUCCESSFULLY Initialised mutex and cond vars.. ");
	}

	{
		//initialise aux instrumentation backend object for non-session worker use
		syslog(LOG_INFO, "InitialiseDelegator: Initialising Auxiliary Instrumentation Backend for Session Delegator thread");
    InstrumentationBackend *instr_ptr = InstrumentationBackendInit (NULL);//no namespace
		if (instr_ptr) {
			sd_ptr->instrumentation_backend_ptr = instr_ptr;
		} else {
			syslog(LOG_INFO, "InitialiseDelegator: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Session Delegator thread");
			sd_ptr->instrumentation_backend_ptr = NULL;
		}
	}

	{
		//initialise aux MessgeQueueBackend object for non-session worker use
		syslog(LOG_INFO, "%s: Initialising Auxiliary MessageQueue Backend for Session Delegator thread...", __func__);
		MessageQueueBackend *msgq_ptr = NULL;
		msgq_ptr = InitialiseMessageQueueBackend(NULL);
		if (msgq_ptr) {
			sd_ptr->msgqueue_pub_ptr=msgq_ptr;
		} else {
			syslog(LOG_INFO, "%s: ERROR: COULD NOT INITIALISE Auxiliary MessageQueueBackend for Session Delegator thread", __func__);
			sd_ptr->msgqueue_pub_ptr = NULL;
		}
	}


	{//Sessions Recycle MAnager
		extern void *ThreadTimerManager (void *);
#if 1
		//to be deleted
		int result = pthread_rwlock_init(&(sd_ptr->recycled_sessions.queue_rwlock), NULL);
		if (result != 0) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_ERR, "InitialiseDelegator: TERMINATING (errno: '%d'): COULD NOT INITIALISE sd_ptr->recycled_sessions.queue_rwlock: error: '%s'...", errno, error_str);

			exit(-1);
		}
#endif
		_InitScheduledJobsStore (GetScheduledJobsStore(), 0);

		result = pthread_create(&(sd_ptr->recycled_sessions.queue_manager_th), NULL, ThreadTimerManager, (void *)GetScheduledJobsStore());
		if (result != 0) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_ERR, "InitialiseDelegator: TERMINATING (errno: '%d'): COULD NOT INITIALISE Timer Manager(TM) thread: '%s'...", errno, error_str);

			exit(-1);
		}

		syslog(LOG_INFO, ">> InitialiseDelegator: SUCCESSFULLY Initialised TimerManager...'");
	}

	sd_ptr->up_status = 1;

	SpawnIOSessionWorkers (sd_ptr);
	SpawnUfServerWorkers (sd_ptr);

	RegisterScheduledJobType (GetScheduledJobsStore(), GetScheduledJobTypeForSessionTimeout());
	AddScheduledJob (GetScheduledJobsStore(), GetScheduledJobForSessionTimeout());

	return 1;

}

__pure ScheduledJobs  * const
GetScheduledJobsStore (void)
{
	static ScheduledJobs scheduled_jobs_store;
	return &scheduled_jobs_store;
}

static void
_InitScheduledJobsStore (ScheduledJobs *scheduled_jobs, size_t count)
{
	InitScheduledJobsStore (scheduled_jobs, 0);
	syslog(LOG_INFO, "%s (pid:'%lu', o:'%p', page_sz:'%d', entries_per_page:'%d'): SUCCESS: Initialised ScheduledJobsStore", __func__, pthread_self(), scheduled_jobs, heap_page_size(), heap_entries_per_page());
}

/**
 * @brief:  Setup andinitialise thetheIPC channel between Workers -> Delegator. Current implementation uses classic simple self-pipe.
 * Each worker thread is handed a Session containing the pipe-set (reader and writer fds).
 */
//http://stackoverflow.com/questions/9028934/how-to-interrupt-epoll-pwait-with-an-appropriate-signal
//http://www.win.tue.nl/~aeb/linux/lk/lk-12.html

static InstanceHolderForSession *
InitDelegatorWorkerInterConnectionPipe (void)
{
	Socket 	*ss_ptr,
					*ds_ptr		=	NULL;
	Session	*sesn_ptr	=	NULL;

	ss_ptr = calloc(1, (sizeof(Socket)));//writer end in main main listening  thread
	ds_ptr = calloc(1, (sizeof(Socket)));//reader end in WorkDelegator thread

	if (!(sesn_ptr = InstantiateSession(ss_ptr, ds_ptr, 0, -1))) {//dont add to sessions hash table
		syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise Worker-Delegator IPC Pipe session: Exiting...", __func__);

		goto exit_error;
	}

	if ((pipe2(sesn_ptr->ipcpipe_fds, O_NONBLOCK)) == -1) {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise Worker-Delegator IPC Pipe (errno:%d)", __func__, errno);

		exit_error:
		free(sesn_ptr);
		free (ss_ptr);
		free(ds_ptr);

		return NULL;
	}

	ss_ptr->type = SOCK_PIPEWRITER;
	ss_ptr->sock = sesn_ptr->ipcpipe_fds[1];//PIPE_WRITE_END;
	strcpy (ss_ptr->address, "pipe.writer.localhost");
	strcpy (ss_ptr->haddress, "pipe.reader.localhost");

	ds_ptr->type = SOCK_PIPEREADER;
	ds_ptr->sock = sesn_ptr->ipcpipe_fds[0];//PIPE_READ_END;
	strcpy (ds_ptr->address, "pipe.reader.localhost");
	strcpy (ds_ptr->haddress, "pipe.writer.localhost");

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IPC);

	syslog(LOG_INFO, "%s: INITIALISED Worker-Delegator IPC Pipe (cid:'%lu') connection: WRITER: '%s:%d' READER: '%s:%d'",__func__, sesn_ptr->session_id, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

	InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
	SetInstance(instance_sesn_ptr, sesn_ptr);

	return instance_sesn_ptr;

}

static Session *
DestructDelegatorWorkerInterConnectionPipe (SessionsDelegator *sd_ptr)
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
UfsrvGetSessionWorkersSize(void)
{
	return sessions_delegator.setsize;
}

#ifdef CONFIG_USE_LOCKLESS_SESSION_WORKERS_QUEUE

static void
SpawnIOSessionWorkers (SessionsDelegator *sd_ptr)
{
	if (sd_ptr) {
		extern void *ThreadWebSockets (void *);

		//create a set to hold worker->delegator ipc primitives (currently self-pipes)
		sd_ptr->worker_delegator_ipc = calloc(1, (sizeof(InstanceHolderForSession *) * sd_ptr->setsize));

		//create a set of Session i/o workers
		sd_ptr->session_worker_ths = malloc(sizeof(pthread_t) * sd_ptr->setsize);
#if __VALGRIND_DRD
		VALGRIND_CREATE_MEMPOOL(sd_ptr->session_worker_ths, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->session_worker_ths, sizeof(pthread_t) * sd_ptr->setsize);
#endif

		//allocate one whole continuous chunk for all threads, include queue storage: payload + container
		sd_ptr->sessions_work_queues = calloc(sd_ptr->setsize, sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE*sizeof(QueueClientData *)));
		void *allocation_tracker = sd_ptr->sessions_work_queues;
#if __VALGRIND_DRD
		VALGRIND_CREATE_MEMPOOL(sd_ptr->sessions_work_queues, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->sessions_work_queues, sd_ptr->setsize * (sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *))));
#endif

		WorkerThreadCreationContext *thread_contexts = calloc(sd_ptr->setsize, sizeof(WorkerThreadCreationContext));
#if __VALGRIND_DRD
		VALGRIND_CREATE_MEMPOOL(thread_contexts, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(thread_contexts, sd_ptr->setsize*sizeof(WorkerThreadCreationContext));
#endif

		int i;
		int result;
		//Session *sesn_ptr_ipc = NULL;
		InstanceHolderForSession *instance_sesn_ptr_ipc;
		WorkerThreadCreationContext *thread_context;
		for (i=0; i!=sd_ptr->setsize; i++) {
			if ((instance_sesn_ptr_ipc = InitDelegatorWorkerInterConnectionPipe())) {
#if __VALGRIND_DRD
				VALGRIND_MEMPOOL_ALLOC(sd_ptr->sessions_work_queues, allocation_tracker, sizeof(LocklessSpscQueue));
				VALGRIND_MEMPOOL_ALLOC(sd_ptr->sessions_work_queues, allocation_tracker+sizeof(LocklessSpscQueue), (sizeof(LocklessSpscQueue)+(sizeof(QueueClientData *)*CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE)));

				VALGRIND_MEMPOOL_ALLOC(thread_contexts, thread_contexts+(i*sizeof(WorkerThreadCreationContext)), sizeof(WorkerThreadCreationContext));

				VALGRIND_MEMPOOL_ALLOC(sd_ptr->session_worker_ths, &(sd_ptr->session_worker_ths[i]), sizeof(pthread_t));
#endif
				LocklessSpscQueue *lockless_queue = allocation_tracker;
				QueueClientData 	**queue_storage = allocation_tracker+sizeof(LocklessSpscQueue);
				LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE);

				(sd_ptr->worker_delegator_ipc[i]) = instance_sesn_ptr_ipc;

				thread_context = thread_contexts + (i * sizeof(WorkerThreadCreationContext));
				thread_context->idx = i;
				thread_context->ipc_pipe = instance_sesn_ptr_ipc;
				thread_context->queue = lockless_queue;
				result = pthread_create(&(sd_ptr->session_worker_ths[i]), NULL, ThreadWebSockets, thread_context);
				if (result != 0) {
					syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, sd_ptr->setsize, i);
					exit (-1);
				}

        allocation_tracker += (sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE));
			}
	   }//for

    statsd_gauge(sd_ptr->instrumentation_backend_ptr, "worker.work.handshake_failed", 0);

		syslog(LOG_ERR, "%s (queues:'%p'): SUCCESSFULLY spawned '%d' Session Worker Threads...", __func__, sd_ptr->sessions_work_queues, sd_ptr->setsize);
	}

}

#else

/**
 * 	@brief: setup and initialise the Session worker threads responsible for servicing Sessions I/O.
 * 	The delegator is responsible for relying job requests to workers via the Job Queue, wich is protected by pthreads
 * 	mutex and a signaling primitives.
 *
 * 	The workers can communicate with the delegator via a seperate ipc channel. Thesignalling mechanism there is self-pipes. The fd for
 * 	which are monitored in epoll, along with the regular tcp sockets (one listening + as many open connection sockets)
 */
static void
SpawnIOSessionWorkers (SessionsDelegator *sd_ptr)

{
	if (sd_ptr)
	{
		extern void *ThreadWebSockets (void *);

		//create a set to hold worker->delegator ipc primitives (currently self-pipes)
		sd_ptr->worker_delegator_ipc=calloc(1, (sizeof(Session *)*sd_ptr->setsize));

		//create a set of Session i/o workers
		sd_ptr->session_worker_ths=malloc(sizeof(pthread_t)*sd_ptr->setsize);
		if (sd_ptr->session_worker_ths==NULL)
		{
			syslog(LOG_ERR, "%s: FATAL: could not allocate memory for Session Worker Threads (requested: '%d'): terminating...", __func__, sd_ptr->setsize);
			exit (-1);
		}

		int i;
		int result;
		Session *sesn_ptr_ipc=NULL;
		for (i=0; i!=sd_ptr->setsize; i++)
		{
			if ((sesn_ptr_ipc=InitDelegatorWorkerInterConnectionPipe()))
			{
				(sd_ptr->worker_delegator_ipc[i])=sesn_ptr_ipc;
				result=pthread_create( &(sd_ptr->session_worker_ths[i]), NULL, ThreadWebSockets, (void *)sesn_ptr_ipc);
				if (result!=0)
				{
					syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, sd_ptr->setsize, i);
					exit (-1);
				}
			}
	   }//for

		syslog(LOG_ERR, "%s: SUCCESSFULLY spawned '%d' Session Worker Threads...", __func__, sd_ptr->setsize);
	}

}

#endif


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

	sd_ptr->ufsrv_thread_pool.workers=malloc(sizeof(pthread_t)*pool_size);

	//allocate one whole continuous chunk for all threads, include queue storage
	sd_ptr->ufsrv_thread_pool.ufsrv_work_queues=calloc(pool_size, sizeof(LocklessSpscQueue)+(CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE*sizeof(QueueClientData *)));
	void *allocation_tracker=sd_ptr->ufsrv_thread_pool.ufsrv_work_queues;

	int i;
	int result;
	for (i=0; i!=pool_size; i++)
	{
		LocklessSpscQueue *lockless_queue=allocation_tracker;
		QueueClientData 	**queue_storage=allocation_tracker+sizeof(LocklessSpscQueue);
		LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE);
		allocation_tracker+=(sizeof(LocklessSpscQueue)+(sizeof(QueueClientData *)*CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE));

		result=pthread_create( &(sd_ptr->ufsrv_thread_pool.workers[i]), NULL, ThreadUFServerWorker, (void *)lockless_queue);
		if (result!=0)
		{
			syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, pool_size, i);
			exit (-1);
		}
	 }//for

	syslog(LOG_INFO, "%s (queues:'%p': SUCCESSFULLY spawned '%d' UFServer Worker Threads...", __func__, sd_ptr->ufsrv_thread_pool.ufsrv_work_queues, pool_size);

}

#else

//non session worker threads, performing routine or regular tasks other than responding to session i/o
static void
SpawnUfServerWorkers (SessionsDelegator *sd_ptr)
{
	if (likely(IS_PRESENT(sd_ptr))) {
		extern void *ThreadUFServerWorker (void *);
		int pool_size = 3;

		lua_getglobal(masterptr->lua_ptr, "ufsrv_workers_thread_pool");
		if (!lua_isnumber(masterptr->lua_ptr, -1)) {
			syslog(LOG_ERR, "SpawnUfServerWorkers: ERROR: UNRECOGNISED VALUE SET FOR 'ufsrv_workers_thread_pool': using default '%d'", _CONFIGDEFAULT_MAX_UFSRV_WORKERS);
		}
		else	pool_size = (int)lua_tonumber(masterptr->lua_ptr, -1);

		if (pool_size < 1) pool_size = _CONFIGDEFAULT_MAX_UFSRV_WORKERS;

		sd_ptr->ufsrv_thread_pool.workers=malloc(sizeof(pthread_t)*pool_size);
#if __VALGRIND_DRD
		VALGRIND_CREATE_MEMPOOL(sd_ptr->ufsrv_thread_pool.workers, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->ufsrv_thread_pool.workers, sizeof(pthread_t) * pool_size);
#endif

		int i;
		int result;
		for (i=0; i!=pool_size; i++) {
#if __VALGRIND_DRD
			VALGRIND_MEMPOOL_ALLOC(sd_ptr->ufsrv_thread_pool.workers, &(sd_ptr->ufsrv_thread_pool.workers[i]), sizeof(pthread_t));
#endif
			result = pthread_create( &(sd_ptr->ufsrv_thread_pool.workers[i]), NULL, ThreadUFServerWorker, (void *)sd_ptr);
			if (result!=0) {
				syslog(LOG_ERR, "SpawnUfServerWorkers: FATAL: COULD NOT spawn UFServer Worker Threads (requested: '%d', iteration: '%d'): terminating...", pool_size, i);
				exit (-1);
			}
		}//for

		syslog(LOG_INFO, "SpawnUfServerWorkers: SUCCESSFULLY spawned '%d' UFServer Worker Threads...", pool_size);
	}

}

#endif

/**
 *  Edge triggered: notification is on state of readiness event, not state of buffer ie whether it has has unread data in it or not. The latter is how level triggered works.
 *
 *  another way to put it:  transition from empty to non-empty for reads and from full to not-full for writes.
 *  Thus, to enable the next trigger, the buffers first have to be driven to empty on read/full on write (i.e. EAGAIN).
 *
 *  for listening sockets see http://stackoverflow.com/questions/14221339/epoll-wait-on-a-listener-socket-and-spurious-failures
 *
 */
static int
AddWorkEvent (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr)
{
	struct epoll_event epoll_event = {};
  //epoll_event.events=0;//just to make sure it is resent to known state
  epoll_event.events |= EPOLLIN;
  epoll_event.events |= EPOLLOUT;
  epoll_event.events |= EPOLLET;//NOT leaving to default level triggered
  epoll_event.events |= EPOLLRDHUP;
  epoll_event.data.u64 = 0;
  epoll_event.data.ptr = instance_sesn_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_ADD, sesn_ptr->ssptr->sock, &epoll_event) == -1) {
		char *error_str;

		error_str = epoll_ctl_error_freeme(errno);
		syslog (LOG_DEBUG, "%s (pid='%lu' o:'%p'): COULD NOT ADD (error: '%s') new event (fd='%d') to MonitoredEvents... (cid='%lu')", __func__, pthread_self(), sesn_ptr, error_str, sesn_ptr->ssptr->sock, SESSION_ID(sesn_ptr));
		free(error_str);
		return 0;
	} else {
#ifdef __UF_FULLDEBUG
    	syslog (LOG_DEBUG, "%s (pid:'%lu' o:'%p'): Adding new event (fd='%d') to MonitoredEvents... (cid='%lu')", __func__, pthread_self(), sesn_ptr, sesn_ptr->ssptr->sock, SESSION_ID(sesn_ptr));
#endif
    }

	return 1;

}

static char *
epoll_ctl_error_freeme (int error)
	{
		char *e_str=NULL;

		switch (error)
		{
			case EEXIST:
				e_str=mystrdup("'EEXIST' the supplied file descriptor fd is already registered with this epoll instance");
				return e_str;
			break;

			case EBADF:
						e_str=mystrdup("'EBADF' error: invalid fd'");
						return e_str;
			break;

			case EINVAL:
						e_str=mystrdup("'EINVAL' fd is the same a epfd, or the requested operation op is not supported by this interface'");
						return e_str;
			break;

			case ENOENT:
						e_str=mystrdup("'ENOENT' 'fd is not registered with this epoll instance'");
						return e_str;
			break;

			case ENOMEM:
						e_str=mystrdup("'ENOMEM' 'NOT ENOUGH MEMORY'");
						return e_str;
			break;

			case ENOSPC:
						e_str=mystrdup("'ENOSPC' 'error: imit imposed by /proc/sys/fs/epoll/max_user_watches was encountered while trying to register'");
						return e_str;
			break;

			default:
				return mystrdup("ERROR NOT REGISTERED");
		}
	}

__unused static int
RearmSessionInMonitoredWorkEvents (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr)
{
	struct epoll_event epoll_event = {};
	epoll_event.events |= EPOLLIN;//|EPOLLONESHOT;
	epoll_event.events |= EPOLLET;//NOT leaving to default level triggered
	epoll_event.events |= EPOLLRDHUP;
	epoll_event.events |= EPOLLONESHOT;
	epoll_event.data.u64 = 0;
	epoll_event.data.ptr = instance_sesn_ptr;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if ((epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_MOD, sesn_ptr->ssptr->sock, &epoll_event)) == -1) {
		char *error_str;

		error_str = epoll_ctl_error_freeme(errno);
		syslog (LOG_DEBUG, "%s (pid='%lu' o:'%p'): COULD NOT REARM ONESHOT EVENT (error: '%s') new event (fd='%d') to MonitoredEvents... (cid='%lu')",
				__func__, pthread_self(), sesn_ptr, error_str, SESSION_SOCKETFD(sesn_ptr), SESSION_ID(sesn_ptr));
		free(error_str);

		return 0;
	} else {

	}

	return 1;

}

int
AddSessionToMonitoredWorkEvents (InstanceHolderForSession *instance_sesn_ptr)
{
  return AddWorkEvent (sessions_delegator_ptr, instance_sesn_ptr);

}

int
RemoveSessionToMonitoredWorkEvents (InstanceHolderForSession *instance_sesn_ptr)
{
		return RemoveWorkEvent (sessions_delegator_ptr, instance_sesn_ptr);
}

static int
RemoveWorkEvent (SessionsDelegator *sd_ptr, InstanceHolderForSession *instance_sesn_ptr)
{
  struct epoll_event epoll_event = {0};

    //epoll_event.events=0;//just to make sure it is resent to known state
	epoll_event.events |= EPOLLIN;
	epoll_event.events |= EPOLLOUT;
	epoll_event.data.u64 = 0;
	epoll_event.data.ptr = instance_sesn_ptr;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_DEL, sesn_ptr->ssptr->sock, &epoll_event) == -1) {
#ifdef __UF_FULLDEBUG
	  //can be fale positive, as fd can be automatically removed by the kernel
		char *error_str;
		error_str=epoll_ctl_error_freeme(errno);
		syslog (LOG_INFO, "%s (pid:'%lu', o:'%p', cid:'%lu', socket_fd:'%d', error:'%s'): ERROR: COULD NOT REMOVE event from MonitoredEvents...)", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), error_str);
		free(error_str);
#endif
		return 0;//error
	} else {
#ifdef __UF_FULLDEBUG
		syslog (LOG_DEBUG, "%s (pid='%lu'): SUCCESSFULLY REMOVED event (fd='%d') from MonitoredEvents... (cid='%lu')", __func__, pthread_self(), sesn_ptr->ssptr->sock, sesn_ptr->session_id);
#endif
	}

	return 1;


}

#ifndef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
inline static int
NewConnectionsQueueLock (int try_flag)
{
	int lock_state;

	if(try_flag)
	{
		lock_state = pthread_mutex_trylock(&(sessions_delegator_ptr->new_connections.queue_mutex));
		if (lock_state==0)
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid='%lu' lock:10:1 ): SUCCESS: ACQUIRED TRY-LOCK", __func__, pthread_self());
#endif
		}

		else
		{
			char *err_str=thread_error(errno);
			syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT ACQUIRE TRY-LOCK (errno='%d'): '%s'",
					__func__, pthread_self(), errno, err_str);free(err_str);
		}
	}
	else
	{
		lock_state = pthread_mutex_lock(&(sessions_delegator_ptr->new_connections.queue_mutex));
		if (lock_state==0)
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid='%lu' lock:10:1 ): SUCCESS: ACQUIRED LOCK", 	__func__, pthread_self());
#endif
		}
		else
		{
			char *err_str=thread_error(errno);
			syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT ACQUIRE LOCK (errno='%d'): '%s'",
					__func__, pthread_self(), errno, err_str);free(err_str);
		}
	}

	return lock_state;

}


inline static int
NewConnectionsQueueUnLock (void)
{
	int lock_state = pthread_mutex_unlock(&(sessions_delegator_ptr->new_connections.queue_mutex));

	if (lock_state==0)
	{
		//syslog(LOG_DEBUG, "%s: (pid='%lu' lock:10:-1 ): SUCCESS: RELEASED LOCK", __func__, pthread_self());
	}
	else
	{
		char *err_str=thread_error(errno);
		syslog(LOG_WARNING, "%s: (pid:'%lu'): ERROR: COULD NOT RELEASE LOCK (errno='%d'): '%s'",
				__func__, pthread_self(),  errno, err_str); free(err_str);
	}

	return lock_state;

}

#endif

inline int
WorkQueueLock (SessionsDelegator *sd_ptr, int try_flag)
{
	int lock_state;

	if(try_flag)
	{
		lock_state = pthread_mutex_trylock(&(sd_ptr->work_queue_mutex));
		if (lock_state==0)
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid='%lu' lock:10:1 ): SUCCESS: ACQUIRED TRY-LOCK", __func__, pthread_self());
#endif
		}

		else
		{
			char *err_str=thread_error(errno);
			syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT ACQUIRE TRY-LOCK (errno='%d'): '%s'",
					__func__, pthread_self(), errno, err_str); free(err_str);
		}
	}
	else
	{
		lock_state = pthread_mutex_lock(&(sd_ptr->work_queue_mutex));
		if (lock_state==0)
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid='%lu' lock:30:1 ): SUCCESS: ACQUIRED LOCK", __func__, pthread_self());
#endif
		}
		else
		{
			char *err_str=thread_error(errno);
			syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT ACQUIRE LOCK (errno='%d'): '%s'",
					__func__, pthread_self(), errno, err_str);free(err_str);
		}
	}

	return lock_state;

}

inline int
WorkQueueUnLock (SessionsDelegator *sd_ptr)
{
	int lock_state = pthread_mutex_unlock(&(sd_ptr->work_queue_mutex));

	if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s: (pid='%lu' lock:30:-1 ): SUCCESS: RELEASED LOCK", __func__, pthread_self());
#endif
	} else {
		char *err_str = thread_error(errno);
		syslog(LOG_WARNING, "%s: (pid='%lu' lock:30:0 ): ERROR: COULD NOT RELEASE LOCK (errno='%d'): '%s'", __func__, pthread_self(),  errno, err_str); free(err_str);
	}

	return lock_state;

}

/**
 * 	@brief: Add the IPC self-pipe between the Connection Listener -> Work Delegator. This signalling mechanism is used to fetch
 * 	new connections from New Connections Queue. Only the reader side of the pipe fd is plugged into epoll.
 * 	This should last fot the lifetime of the server.
 */
inline static void
AddPipeConnectionToMonitoredEvents (SessionsDelegator *sd_ptr)
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
 * 	@brief: Add the IPC self-pipe between the Session Workers -> Work Delegator. This signalling mechanism is used to request the
 * 	Delegator to re-queue a Session for an I/O iteration by a worker. Only the reader side of the pipe fd is plugged into epoll.
 * 	This should last for the lifetime of the worker thread.
 */
inline static void
AddAllWorkerDelegatorPipeConnectionsToMonitoredEvents (SessionsDelegator *sd_ptr)
{
	int i;
	Session *sesn_ptr_ipc = NULL;
	InstanceHolderForSession *instance_sesn_ptr_ipc;

	for (i=0; i!=sd_ptr->setsize; i++) {
		instance_sesn_ptr_ipc = sd_ptr->worker_delegator_ipc[i];

		struct epoll_event epoll_event = {};
		epoll_event.events = EPOLLIN;//|EPOLLET; //use default line triggered as we want to make sure the pipe is always drained
		epoll_event.data.u64 = 0;
		epoll_event.data.ptr = instance_sesn_ptr_ipc;

		sesn_ptr_ipc = SessionOffInstanceHolder(instance_sesn_ptr_ipc);

		if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_ADD, sesn_ptr_ipc->dsptr->sock, &epoll_event) == -1) {//PIPE READER END is in dsptr not ssptr
			syslog(LOG_ERR, "%s: COULD NOT add pipe connection to events loop: WILL NOT be able to process Worker->Delegator IPC pipe: errno='%d'", __func__, errno);
		} else {
			syslog(LOG_ERR, "%s {cid:'%lu', fd:'%d'}: Worker-Delegator IPC Pipe: Added pipe reader fd to monitored events...", __func__, SESSION_ID(sesn_ptr_ipc), sesn_ptr_ipc->dsptr->sock);
		}
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

	if ((amount_read > 0) && (amount_read == sizeof(char *))) {//hopefully we read 8 bytes
		syslog(LOG_ERR, LOGSTR_WDELEG_WORKERREAD_SUCCESS,  __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), SESSION_ID(SessionOffInstanceHolder(instance_sesn_ptr_target)), amount_read, LOGCODE_WDELEG_WORKERREAD_SUCCESS);

		SessionDecrementReference (instance_sesn_ptr_target, 1);

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

inline static size_t
NewConnectionsPipeDrain(Session *sesn_ptr_ipc, SessionsDelegator *sd_ptr);

/**
 * 	@brief: This is not thread safe as it keeps a static counter for how many times it was invoked. This is not a general
 * 	purpose routine: it is designed to be invoked from a single designated thread.
 */
inline static size_t
NewConnectionsPipeDrain(Session *sesn_ptr_ipc, SessionsDelegator *sd_ptr)
{
	static	size_t drain_threshold_keeper = 0;
	static 	char drain_buffer[CONFIG_NEW_CONNECTIONS_PIPE_SIZE] = {0};

	statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.ipc_pipe_size", drain_threshold_keeper);

	if (++drain_threshold_keeper < CONFIG_NEW_CONNECTIONS_PIPE_DRAIN_THREASHOLD)	return 0;

	//note we use dsptr
	ssize_t amount_read = read(sesn_ptr_ipc->dsptr->sock, drain_buffer, CONFIG_NEW_CONNECTIONS_PIPE_SIZE);
	int errno_this = errno;

	if (amount_read > 0) {
#ifdef __UF_TESTING
		syslog(LOG_ERR, "%s {pid:'%lu', cid_pipe:'%lu', drainer_sz: '%lu', rc:'%lu'}: NewConnectionsDelegatorPipe: DRAINED PIPE", __func__, pthread_self(), SESSION_ID(sesn_ptr_ipc), drain_threshold_keeper, amount_read);
#endif
		if (amount_read > drain_threshold_keeper)	drain_threshold_keeper = amount_read;

		drain_threshold_keeper -= amount_read;

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

#ifdef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE

static void  _AssignSessionWorkersQueues (LocklessSpscQueue **sessions_work_queues, LocklessSpscQueue **session_workers_queues_idx, size_t threads_size);

static void
_AssignSessionWorkersQueues (LocklessSpscQueue **sessions_work_queues, LocklessSpscQueue **session_workers_queues_idx, size_t threads_size)
{
	void *allocation_tracker=sessions_work_queues;

	for (size_t i=0; i<threads_size; i++)
	{
		LocklessSpscQueue *lockless_queue=allocation_tracker;
		session_workers_queues_idx[i]=allocation_tracker;
		allocation_tracker+=(sizeof(LocklessSpscQueue)+(sizeof(QueueClientData *)*CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE));
	}
}

static void *
ThreadWorkerDelegator (void *ptr)
{
	SessionsDelegator *sd_ptr = NULL;

	sd_ptr = (SessionsDelegator *)ptr;
	LocklessSpscQueue *new_connections_queue_ptr =& (sessions_delegator_ptr->new_connections.queue);

	InitialiseDelegator (sd_ptr);

  unsigned 					connections_queue;
  unsigned long 		stat_atomic = 0L;
  QueueClientData 	*client_data_ptr;
  LocklessSpscQueue *session_workers_queues_idx[sd_ptr->setsize];

  _AssignSessionWorkersQueues (sd_ptr->sessions_work_queues, session_workers_queues_idx, sd_ptr->setsize);

  AddPipeConnectionToMonitoredEvents (sd_ptr);
  AddAllWorkerDelegatorPipeConnectionsToMonitoredEvents (sd_ptr);

  //new connections queue processing block
  dequeue:
  connections_queue = 0;//reset state

#ifdef __UF_FULLDEBUG
  //syslog(LOG_DEBUG, "%s (pid='%lu' connection_queu_size:'%lu'): >> BEGIN DEQUEUE: NewConnectionsQueue...", __func__, pthread_self(), new_connections_queue_ptr->nEntries );
#endif

  long long timer_start = GetTimeNowInMicros();

  //retrieve all new connection requests and add them to main event listener
  //while (new_connections_queue_ptr->nEntries!=0)
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
      close (sesn_ptr_new->ssptr->sock);
      SessionReturnToRecycler (instance_sesn_ptr_new, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);
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
    int ready_events_count = epoll_wait(sd_ptr->epoll_handle, sd_ptr->events_container, sd_ptr->setsize, -1);
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
          sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers
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
              int thread_idx = j % sd_ptr->setsize;//round robin worker threads around each ready event
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
        pthread_cond_broadcast(&sd_ptr->queue_not_empty_cond);
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
        er = strerror_r (errno, erbuf, MBUF);

        syslog(LOG_ERR, LOGSTR_WDELEG_EVENTS_POLLERROR, __func__, pthread_self(), errno, er, LOGCODE_WDELEG_EVENTS_POLLERROR);
      }
    }
  }

	return NULL;

}

#else

static void *
ThreadWorkerDelegator (void *ptr)
{
	SessionsDelegator *sd_ptr=NULL;

	sd_ptr = (SessionsDelegator *)ptr;
	Queue *new_connections_queue_ptr = &(sessions_delegator_ptr->new_connections.queue);

	InitialiseDelegator (sd_ptr);

	{
		unsigned 			connections_queue;
		unsigned long stat_atomic = 0L;

		AddPipeConnectionToMonitoredEvents (sd_ptr);
		AddAllWorkerDelegatorPipeConnectionsToMonitoredEvents (sd_ptr);

		//new connections queue processing block
		dequeue:
		#if 1

		connections_queue = 0;//reset state

		//done here before locking to catch failure of the loop below
		statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.queue_size", (ssize_t)new_connections_queue_ptr->nEntries);

		if ((NewConnectionsQueueLock(0)) != 0) {
			//goto dequeue;
		}

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid='%lu' connection_queu_size:'%lu'): >> BEGIN DEQUEUE: NewConnectionsQueue...", __func__, pthread_self(), new_connections_queue_ptr->nEntries );
#endif

		long long timer_start = GetTimeNowInMicros();

		//retrieve all new connection requests and add them to main event listener
		while (new_connections_queue_ptr->nEntries != 0) {
			//1)Retrieve carrier object
			QueueEntry *qe_ptr = deQueue(new_connections_queue_ptr);

			((Session *)qe_ptr->whatever)->when_serviced_end = time(NULL);//corresponding start time was set in AnswerTelnetRequest()

			if (AddWorkEvent (sd_ptr, (Session *)qe_ptr->whatever)) {
			//successs
				//3)destruct carrier object
				syslog(LOG_DEBUG, LOGSTR_WDELEG_NEWCONNECTION_ADDED, __func__, pthread_self(), qe_ptr->whatever, ((Session *)qe_ptr->whatever)->session_id, LOGCODE_WDELEG_NEWCONNECTION_ADDED);
				statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.queue_size", -1);

				free(qe_ptr);
			} else {
				//TODO: FIX RECOVERY: revisit this treatment as it disturbs the order of events
				QueueEntry *qe_ptr2=NULL;

				//statsd_(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.dropped", new_connections_queue_ptr->nEntries);
				//queued connection disappeared
				syslog(LOG_ERR, "%s (pid='%lu'): COULD NOT ADD new event... DROPPING PACKET and SUSPENDING into RECYCLER...", __func__, pthread_self());
				//TODO: FIX object not ready
				//SuspendSession ((Session *)(qe_ptr->whatever), 1);
				free (qe_ptr);
			}

		}//while
		long long timer_end = GetTimeNowInMicros();

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid='%lu'): >> END DEQUEUE: NewConnectionsQueue contains: '%lu' entries...", __func__, pthread_self(), new_connections_queue_ptr->nEntries );
#endif

		statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.new_connections.dequeue.elapsed_time", timer_end-timer_start);

		//same as listener.connection.queue_size in ufsrv.c
		//statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.request.queue_size", new_connections_queue_ptr->nEntries);

		if ((NewConnectionsQueueUnLock()) != 0) {
			//syslog(LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT UN-LOCK NEW CONNECTIONS QUEUE...", __func__, pthread_self());
		}

		#endif
		//end of dequeue

		//main event listener
		while (1 != 2) {
			Session *sesn_ptr;
			///syslog(LOG_DEBUG, "ThreadWorkerDelegator: Blocking on I/O events: epoll_wait...");

			//>>>>>>>>>>>>>>>>>>>>>>>>
			int ready_events_count = epoll_wait(sd_ptr->epoll_handle, sd_ptr->events_container, sd_ptr->setsize, -1);
			//>>>>>>>>>>>>>>>>>>>>>>>>

			statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.queue_size", ready_events_count);

			if (ready_events_count > 0) {
				unsigned j;
				time_t event_loop_start = time(NULL);

				///syslog(LOG_DEBUG, "%s (pid='%lu' ready_events:'%d): --->>> epoll_wait returned: attempting to acquire Session Work Queue lock: I might block if other workers are fetching jobs...", __func__, pthread_self(), ready_events_count);

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
				if ((WorkQueueLock(sd_ptr, 0)) != 0) {
					//continue;
					//TODO: FIX RECOVERY...
				}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				///syslog(LOG_DEBUG, "ThreadWorkerDelegator: SESSION WORK QUEUE MUTEX LOCK ACQUIRED (1)... looping through ready events... ");

				__read_ready_events:
				#if 1

				for (j=0; j<ready_events_count; j++) {
          struct epoll_event *ee_ptr = sd_ptr->events_container + (j * sizeof(struct epoll_event));

					sesn_ptr=(Session *)ee_ptr->data.ptr;

					if (IS_PRESENT(sesn_ptr)) {
						//__vdrd_AnnotateIgnoreVariable(sesn_ptr->event_descriptor);
						//DRD_IGNORE_VAR(sesn_ptr->event_descriptor);
						sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers
						if (sesn_ptr->ssptr->type == SOCK_PIPEWRITER) {//new connection indicator
							//TODO: this implementation needs to be revisited, both types (listener pope as well) should treated the same, but use callbacks
							if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IPC)) {
								///syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKER_REQUEST_RCV, __func__, pthread_self(), SESSION_ID(sesn_ptr), LOGCODE_WDELEG_WORKER_REQUEST_RCV);

								//we have a lock on the Work Queue read off the cid and reinsert it into the queue
								InstanceHolderForSession *instance_sesn_ptr_target = WorkerDelegatorPipeGetSession(sesn_ptr);
								if (sesn_ptr_target) {
									//TODO: not sure I like this hackish implementation: separate into inlined function
									sesn_ptr = sesn_ptr_target;
									goto __atomic_op;
								} else {
									syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKER_NULLREQUEST, __func__, pthread_self(), SESSION_ID(sesn_ptr), LOGCODE_WDELEG_WORKER_NULLREQUEST);
									//back to loop
								}
							}
							else
							{
								//DRD_STOP_IGNORING_VAR(sesn_ptr->event_descriptor);
#ifdef __UF_FULLDEBUG
								syslog(LOG_DEBUG, "%s (pid='%lu' j='%u'): NEW CONNECTION REQUEST Queue...", __func__, pthread_self(), j);
#endif

								NewConnectionsPipeDrain(sesn_ptr, sd_ptr);
								connections_queue=1;
							}
							continue;//redundant
						}
						else
						{
							__atomic_op:

							//__vdrd_AnnotateIgnoreVariable(sesn_ptr->stat);
							//DRD_IGNORE_VAR(sesn_ptr->stat);
							stat_atomic=__sync_add_and_fetch (&sesn_ptr->stat, 0);
							if (SESNSTATUS_IS_SET(stat_atomic, SESNSTATUS_CONNECTED))
							{
								QueueEntry *qe_ptr=NULL;
								//DRD_STOP_IGNORING_VAR(sesn_ptr->stat);
								qe_ptr=AddQueue(&sd_ptr->sessions_work_queue);//remember this is mutex protected
								qe_ptr->whatever=sesn_ptr;
								sesn_ptr->when_signal_start=time(NULL);

								//statsd_gauge(sd_ptr->instrumentation_backend_ptr, "delegator.work.ready_events_queue_size", ready_events_count);

								syslog(LOG_DEBUG, LOGSTR_WDELEG_WORKREQUEST_ADDED,
										__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),j, sd_ptr->sessions_work_queue.nEntries, LOGCODE_WDELEG_WORKREQUEST_ADDED);
							}
							else
							{
								//can happen a session was previously recycled, but we have some residual events in the queue, especially in level triggered mode
								syslog(LOG_NOTICE, LOGSTR_WDELEG_NONCONNECTED_REQUEST,
										__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_WDELEG_NONCONNECTED_REQUEST);
							}
						}
					}//if
					else
					{
						syslog(LOG_ERR, "%s (pid='%lu' loop_counter='%u'): FATAL: sesen_ptr WAS NULL....", __func__, pthread_self(), j);
					}
				}//for

				#endif
				//end read_ready_events

				//do for accumulated new events
				//deliver signal to waiting worker threads
				if (sd_ptr->sessions_work_queue.nEntries>0)
				{
					///syslog(LOG_DEBUG, "%s (pid='%lu' work_queue_size:'%lu'): FINISHED Queueing jobs: SIGNALLING  on 'queue_not_empty_cond' and releasing mutex lock (-1)...", __func__, pthread_self(),sd_ptr->sessions_work_queue.nEntries);

					pthread_cond_broadcast(&sd_ptr->queue_not_empty_cond);
				} else {
					syslog(LOG_DEBUG, "%s (pid='%lu'): NO JOBS WERE QUEUED... Checking if received events contained New Connections requets", __func__, pthread_self());
				}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				//this will set off the other listeners
				if ((WorkQueueUnLock(sd_ptr)) != 0) {
					///syslog(LOG_ERR, "%s (pid='%lu'):  ERROR: COULD NOT UN-LOCK Work Queue (queue size='%lu'):...", __func__, pthread_self(), sd_ptr->sessions_work_queue.nEntries);
				}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				//statsd_timing(sd_ptr->instrumentation_backend_ptr, "delegator.ready_events.processing_time", time(NULL)-event_loop_start);

				if (connections_queue) {
					//this gets panelised a bit as we process all other requests 1st
					//TODO: remove from epoll
					///syslog(LOG_DEBUG, "%s (pid='%lu'): FOUND NEW EVENTS IN NEW CONNECTIONS QUEUE: FETCHING...",
						///	__func__, pthread_self());

					goto dequeue;
				}
			}//events_count>0
			else
			if (ready_events_count==-1)
			{
				if (errno==EINTR)	continue;

				{//TODO: eplo_wait recovery
					char *er;
					char erbuf[MBUF];
					er=strerror_r (errno, erbuf, MBUF);

					syslog(LOG_ERR, LOGSTR_WDELEG_EVENTS_POLLERROR, __func__, pthread_self(), errno, er, LOGCODE_WDELEG_EVENTS_POLLERROR);
				}
			}

		}//event loop
	}//block

	return NULL;

}

#endif	//!CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
