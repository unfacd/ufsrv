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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <thread_context_type.h>
#include <recycler/recycler.h>
#include <sockets.h>
#include <net.h>
#include <session.h>
#include <misc.h>
#include <utils.h>
#include <sys/prctl.h>//for naming thread
#include <nportredird.h>
#include <ufsrv_core/protocol/protocol.h>
#include <ufsrv_core/protocol/protocol_io.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <http_request.h>
#include <delegator_session_worker_thread.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrv_core/ratelimit/ratelimit.h>
#include <uflib/adt/adt_hopscotch_hashtable.h>
#include "hiredis/hiredis.h"

static UFSRVResult *_p_ProcessSessionSocketMessage (InstanceHolderForSession *, SocketMessage *, int);
static inline UFSRVResult *_HandleSessionWorkRequest (InstanceContextForSession *instance_ctx_ptr, SessionsDelegator *sd_ptr, unsigned long session_id_invoked);
static inline UFSRVResult *_HandleSuccessfulWorkRequest (SessionsDelegator *sd_ptr, unsigned long session_id_invoked, UFSRVResult *res_ptr);
static inline UFSRVResult *_HandleMessageForConnectedSession (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, int flag);
inline static UFSRVResult *_HandlePostSuccessfulIncomingHandshake (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr);
static inline UFSRVResult *_InvokeLifecycleCallbackPostHandshake (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr);
static inline UFSRVResult *_InvokeLifecycleCallbackMsgOut (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned long);
inline static bool WorkerDelegatorRaiseRecycleRequest	(InstanceHolderForSession *instance_sesn_ptr, Session *sesn_ptr_ipc);
inline static void _HandleBusySessionLock (InstanceHolderForSession *);

extern /*thread_local*/ __thread ThreadContext ufsrv_thread_context;

extern ufsrv *const masterptr;

extern  const  Protocol *const protocols_registry_ptr;
extern SessionsDelegator *const sessions_delegator_ptr;


/*
 * 	@brief: this hides the implementation details of raising requests back to the Delegator. We use pthread_getspecific, but we coukd
 * 	pass the pipe Session object directly, because it is known to the thread. To keep it more general, we fetch that value using key.
 * 	@param sesn_ptr_this: the Session for which we are requesting a rerun of the io cycle. ie. self. Session is transporting its address across
 * 	the ipc pipe
 * 	@param sesn_ptr_ipc: this is the session which belongs to the pipe, it is of interest because it knows the pipe socket fd. if not known,
 * 	we query it via thread local key.
 */
inline static bool
WorkerDelegatorRaiseRecycleRequest	(InstanceHolderForSession *instance_sesn_ptr_this, Session *sesn_ptr_ipc)
{
	extern SessionsDelegator *const sessions_delegator_ptr;
	Session *sesn_ptr = NULL;
	Session *sesn_ptr_this = SessionOffInstanceHolder(instance_sesn_ptr_this);

	if (sesn_ptr_ipc)	sesn_ptr = sesn_ptr_ipc;
	else 							sesn_ptr = pthread_getspecific(THRKEY_WORKER_DELEGATOR_PIPE(sessions_delegator_ptr));

	if (IS_PRESENT(sesn_ptr)) {
		unsigned long session_id = SESSION_ID(sesn_ptr_this);//target cid is in sesn_ptr_this
		ssize_t rc = 0;

		SessionIncrementReference(instance_sesn_ptr_this, 1);//this is necessary to prevent session being killed mid-cycle by the Timeout manager. Decremented at WorkerDelegatorPipeGetSession()

		//send the address through, we are in the same family
		rc = write (sesn_ptr->ssptr->sock, (char *)&instance_sesn_ptr_this, sizeof(char *));
		if (rc > 0) {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, LOGSTR_TSWORKER_WDP_SUCCESS_WRITE, __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), LOGCODE_TSWORKER_WDP_SUCCESS_WRITE);
#endif

			SESNSTATUS_UNSET(sesn_ptr_this->stat, SESNSTATUS_RECYCLEREQUEST);

			return true;
		} else {
			SessionDecrementReference(instance_sesn_ptr_this, 1);
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_WDP_BROEKN_WRITE, __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), errno, LOGCODE_TSWORKER_WDP_BROEKN_WRITE);
		}
	} else {
		syslog(LOG_NOTICE, LOGSTR_TSWORKER_WDP_MISSING_OBJ, __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), LOGCODE_TSWORKER_WDP_MISSING_OBJ);
	}

	return false;

}

#ifdef CONFIG_USE_LOCKLESS_SESSION_WORKERS_QUEUE

void *
ThreadWebSockets (void *ptr)
{
	long long service_start,
						service_end;
	UFSRVResult 			 ufsrv_result					= {0};
	HttpRequestContext http_request_context = {0};
	RequestRateLimitStatus ratelimit_status = {0};
	HopscotchHashtableConfigurable locked_objects_store = {{0}};
	WorkerThreadCreationContext *th_ctx_ptr = (WorkerThreadCreationContext *)ptr;
	extern SessionsDelegator *const sessions_delegator_ptr;

	SessionsDelegator *const sd_ptr = sessions_delegator_ptr;
	InstanceHolderForSession *instance_sesn_ptr_ipc = th_ctx_ptr->ipc_pipe; //worker-delegator ipc pipe fds
  Session *sesn_ptr_ipc = SessionOffInstanceHolder(instance_sesn_ptr_ipc);

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufSessnWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	__init_block:
	#if 1

	pthread_setspecific(masterptr->threads_subsystem.ufsrv_thread_context_key, (void *)&ufsrv_thread_context);

	hopscotch_init(&locked_objects_store.hashtable, CONFIG_THREAD_LOCKED_OBJECTS_STORE_PFACTOR);
	locked_objects_store.keylen = 0;
	locked_objects_store.keylen = 64;
	locked_objects_store.hash_func = (uint64_t (*)(uint8_t *, size_t))inthash_u64;

	ufsrv_thread_context.ht_ptr = &locked_objects_store;

	ufsrv_thread_context.res_ptr = &ufsrv_result;

	//setup key for storing the value of worker-delegator pipe Session *.
	//We may not need this key outside the context of this function, as the session is passed down from thread parent
	pthread_setspecific(THRKEY_WORKER_DELEGATOR_PIPE(sessions_delegator_ptr), (void *)sesn_ptr_ipc);

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		//makesure you initialise all keys in UFSRVThreadsOnceInitialiser (void);
		if (IS_PRESENT(InitialiseHttpRequestContext(&http_request_context, 0))) {
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_http_request_context_key, (void *)&http_request_context);//TODO: move key to delegator structure
      ufsrv_thread_context.http_request_context = &http_request_context;
		} else {
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit(-1);
		}

		syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Session Worker thread: '%lu'...", __func__, &http_request_context, pthread_self())
		;
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	InstrumentationBackend *instr_ptr = NULL;
	instr_ptr = InstrumentationBackendInit (NULL);//no namespace
	if (instr_ptr) {
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key, (void *)instr_ptr);//TODO: move key to delegator structure
    ufsrv_thread_context.instrumentation_backend = instr_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Session Worker thread: '%lu'...", __func__, pthread_self());
	}

	syslog(LOG_DEBUG, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Session Worker thread: '%lu'...", __func__, instr_ptr, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	PersistanceBackend *per_ptr = NULL;
	per_ptr = InitialisePersistanceBackend(NULL);
	if (per_ptr) {
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_data_key, (void *)per_ptr);//TODO: move key to delegator structure
    ufsrv_thread_context.persistance_backend = per_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE persistence for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised Persistence Backend for Session Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		UserMessageCacheBackend *per_ptr_usrmsg = NULL;
		per_ptr_usrmsg = InitialiseCacheBackendUserMessage(NULL);
		if (per_ptr_usrmsg) {
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key, (void *)per_ptr_usrmsg);//TODO: move key to delegator structure
      ufsrv_thread_context.usrmsg_cachebackend = per_ptr_usrmsg;
		} else {
		  syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend UserMessage  for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit (-1);
		}

		syslog(LOG_INFO, "%s: SUCCESS (%p): Initialised Cache Backend UserMessage for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	FenceCacheBackend *per_ptr_fence = NULL;
	per_ptr_fence = InitialiseCacheBackendFence(NULL);
	if (per_ptr_fence) {
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_fence_key, (void *)per_ptr_fence);//TODO: move key to delegator structure
    ufsrv_thread_context.fence_cachebackend = per_ptr_fence;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend Fence  for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s (%p): SUCCESS: Initialised Cache Backend Fence for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	struct _h_connection *db_ptr = NULL;
	db_ptr = InitialiseDbBackend();
	if (db_ptr) {
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure
    ufsrv_thread_context.db_backend = db_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Session Worker thread: '%lu'...", __func__, pthread_self());


	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	MessageQueueBackend *mq_ptr = NULL;
	mq_ptr = InitialiseMessageQueueBackend(NULL);
	if (mq_ptr) {
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key, (void *)mq_ptr);//TODO: move key to delegator structure
    ufsrv_thread_context.msgqueue_backend = mq_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS Initialised MessageQueue Publisher backend for Session Worker thread: '%lu'...", __func__, pthread_self());
	syslog(LOG_INFO, "%s: --> Launching into main loop: pid:'%lu', ufsrv_th_ctx:'%p', th_ctx:'%p', idx:'%lu', queue:'%p'...", __func__, pthread_self(), &ufsrv_thread_context, th_ctx_ptr, th_ctx_ptr->idx, th_ctx_ptr->queue);

	#endif
	//end init_block

	while (1) {
		unsigned long stat_atomic = 0;
    //Session 	*sesn_ptr;
//    InstanceHolderForSession *instance_sesn_ptr;
    InstanceContextForSession instance_context = {0};

		syslog(LOG_DEBUG, "%s (pid:'%lu): --------- START MAIN LOOP ------- ", __func__, pthread_self());

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu'): BEGIN COND_WAIT EVENT: Acquiring work queue mutex lock and fetching Session... I may block", __func__, pthread_self());
#endif

		if ((WorkQueueLock(sd_ptr, 0)) != 0) {
			syslog(LOG_NOTICE, "%s (pid:'%lu): ERROR: COULD NOT ACQUIRE WORK QUEUE LOCK: looping gain.... ", __func__, pthread_self());
			continue;
		}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		while (!(LamportQueuePop(th_ctx_ptr->queue, (QueueClientData **)&(instance_context.instance_sesn_ptr))) && (sd_ptr->up_status==1)) {
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "ThreadWebSockets (3:2 pid:'%lu' lock:30:-1 ): Mutex automatically released: Blocking on condition: waiting for signal: queue_not_empty_cond", pthread_self());
#endif
			pthread_cond_wait(&(sd_ptr->queue_not_empty_cond),	&(sd_ptr->work_queue_mutex));
		}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu): >>> RECIEVED WORK SIGNAL", __func__, pthread_self());
#endif

		//lock now acquired automatically by pthreads.. we unlock at the end

//		sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
    instance_context.sesn_ptr = SessionOffInstanceHolder(instance_context.instance_sesn_ptr);

		if (sd_ptr->up_status == 0) {
			syslog(LOG_INFO, "%s {pid:%lu}: SessionDelegator is shutting down: releasing mutext lock: exiting...", __func__, pthread_self());

			WorkQueueUnLock(sd_ptr);
			pthread_exit(NULL);
		}

		WorkQueueUnLock(sd_ptr);//other threads are now free to acquire the lock and dequeue further

		__atomic_op:
		stat_atomic = __sync_add_and_fetch(&(instance_context.sesn_ptr->stat), 0);
		if (SESNSTATUS_IS_SET(stat_atomic, SESNSTATUS_IOERROR)) {
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN_OOB, __func__, pthread_self(), instance_context.sesn_ptr, SESSION_ID(instance_context.sesn_ptr), LOGCODE_TSWORKER_FAULTYSESN_OOB);

			//RemoveSessionToMonitoredWorkEvents(sesnptr);

			continue;
		}

		//>>>>>>>>>>>>>>>>>>>>>>>
		SessionLockRWCtx(THREAD_CONTEXT_PTR, instance_context.sesn_ptr, _LOCK_TRY_FLAG_TRUE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_HandleBusySessionLock(instance_context.instance_sesn_ptr);
			continue;
		}
		//>>>>>>>>>>>>>>>>>>>>>>>

		//>>>>>>>> Session successfully locked

		//this is to trap a rare scenario where a session which is currently in recycler yet still in epoll's list
		if (SESNSTATUS_IS_SET(instance_context.sesn_ptr->stat, SESNSTATUS_RECYCLED)) {
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN,	__func__, pthread_self(), instance_context.sesn_ptr, SESSION_ID(instance_context.sesn_ptr), LOGCODE_TSWORKER_FAULTYSESN);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLockCtx (THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);
			//>>>>>>>>>>>>>>>>>>>>>>>

			continue;
		}

		//how much time elapsed since work was initially signalled
		//statsd_timing(sd_ptr->instrumentation_backend_ptr, "worker.work.signal_elapsed_time", (sesnptr->when_signal_end=time(NULL))-sesnptr->when_signal_start);

		//__check_busy_session:
		//this can happen with long request queue and the session was terminated/suspended earlier
		if (SESNSTATUS_IS_SET(instance_context.sesn_ptr->stat, SESNSTATUS_SUSPENDED )) {
			//TODO: We should fetch the message to disarm the event
			syslog(LOG_NOTICE, "%s (pid:%lu, o:'%p', cid:%lu): RECEIVED EVENT FOR A SUSPENDED SESSION: WON'T UNSUSPENDING -> UNLOCKING and RETURNING...", __func__, pthread_self(), instance_context.sesn_ptr, SESSION_ID(instance_context.sesn_ptr));

      //>>>>>>>>>>>>>>>>>>>>>>>
      SessionUnLockCtx (THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);
      //>>>>>>>>>>>>>>>>>>>>>>>

			continue; //back to cond_wait
		}

		//TODO: how did acquire the lock if the session is actively servicing?
		if (SESNSTATUS_IS_SET(instance_context.sesn_ptr->stat, SESNSTATUS_INSERVICE )) {
			syslog(LOG_NOTICE, "%s (pid:%lu, o:'%p', cid:%lu): RECEIVED EVENT for IN-SERVICE Session: (NOT) INSERTING in SocketMessageQueue (msg count='%lu')...", __func__, pthread_self(), instance_context.sesn_ptr, SESSION_ID(instance_context.sesn_ptr), instance_context.sesn_ptr->message_queue_in.queue.nEntries);

			//statsd_inc(instance_context.sesn_ptr->instrumentation_backend, "worker.in_event.serviced", 1.0);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLockCtx (THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);
			//>>>>>>>>>>>>>>>>>>>>>>>

			//back to cond_wait
			continue;
		}
		//end check_busy_session

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		__session_in_service:
		SESNSTATUS_SET(instance_context.sesn_ptr->stat, SESNSTATUS_INSERVICE);
		service_start = GetTimeNowInMicros();
		LoadSessionWorkerAccessContext (instance_context.sesn_ptr);

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu cid:%lu proto:'%d'): END COND_WAIT EVENT: Session retrieved: performing Session I/O work...",
				__func__, pthread_self(), SESSION_ID(sesnptr), PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesnptr))));
#endif

		//do work
		{
			unsigned long		session_id_invoked;
			Session 				*sesn_ptr_processed	= NULL;
			UFSRVResult 		*res_ptr;
			struct epoll_event	*ee_ptr  = NULL;

			ee_ptr = (struct epoll_event *)instance_context.sesn_ptr->event_descriptor;
			if (IS_PRESENT(ee_ptr)) {
        instance_context.sesn_ptr->when_serviced_start = time(NULL);//service_start/1000000UL;

				session_id_invoked = SESSION_ID(instance_context.sesn_ptr);

				statsd_inc(instance_context.sesn_ptr->instrumentation_backend, "session_worker.request", 1.0);

				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
				//this may return a suspended session
				res_ptr = _HandleSessionWorkRequest (&instance_context, sd_ptr, session_id_invoked);//we always return a session back regardless
        InstanceHolderForSession *instance_sesn_ptr_aux = (InstanceHolderForSession *)res_ptr->result_user_data;

        if (unlikely(IS_EMPTY(instance_sesn_ptr_aux))) {
          syslog(LOG_ERR, "%s (pid:%lu, o:'%p', cid_invoked:'%lu'): SEVERE ERROR: WE LOST REFERENCE TO SESSION...", __func__, pthread_self(), instance_context.sesn_ptr, session_id_invoked);
          continue;
        }

        Session *sesn_ptr_aux = SessionOffInstanceHolder(instance_sesn_ptr_aux);
				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				SESNSTATUS_UNSET(sesn_ptr_aux->stat, SESNSTATUS_INSERVICE);

				//All error handling happens at lower level. Here we are only interested if the Session is still live or suspended
				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_SUSPENDED)) {
					//two rules apply:
					//1) if _RESULT_TYPE_SUCCESS means user initiated quit, so we hard suspend
					//2)if _RESULT_TYPE_ERROR we check if protocol allow for grace soft period

					if (_RESULT_TYPE_SUCCESS(res_ptr)) {
						//all statements with '///' intentionally disabled
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					} else if ((_RESULT_TYPE_ERROR(res_ptr)) &&
						            (!_PROTOCOL_CTL_RETAIN_SESSION_ON_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_aux)))))) {
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					}
				}

				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLEREQUEST)) {
					WorkerDelegatorRaiseRecycleRequest	(instance_sesn_ptr_aux, NULL);
					//TODO: unset SESNSTATU_RECYCLE if fail
				}

				{
					size_t queue_sz = 0;

					//quick atomic check as we don't hold the socketmessage queue lock, other threads may still have logged something
					if ((queue_sz = __sync_add_and_fetch (&(SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr_aux)), 0)) > 0) {
						syslog(LOG_DEBUG, LOGSTR_TSWORKER_QUEUE_POST_REQUEST, __func__, pthread_self(),sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), queue_sz, LOGCODE_TSWORKER_QUEUE_POST_REQUEST);

						WorkerDelegatorRaiseRecycleRequest	(instance_sesn_ptr_aux, NULL);
					}
				}

				//>>>>>>>>>>>>>>>>>>>>>>>
				service_end = GetTimeNowInMicros();
				sesn_ptr_aux->when_serviced_end = time(NULL);//service_end/1000000UL;
				statsd_timing(pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key), "worker.session.service.elapsed_time", (service_end-service_start));

				SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_aux, __func__);

#if 0
				//at the moment this semantic is disabled. Kicking off session in this loop has proved problematic
				//instead, we rely on timer thread to catch up with it
				if (recycle_flag) {
					//IMPORTANT to only add to recycler after session has been unlocked and completely reset
					SESNSTATUS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLED);

					RecyclerPut(1, (RecyclerClientData *)sesn_ptr_aux, (ContextData *)NULL, 0);
					recycle_flag = false;
				}
#endif
				//>>>>>>>>>>>>>>>>>>>>>>>

				//else the Session either destructed or suspended so we don't care
			} else {
				syslog(LOG_ERR, "%s (pid:%lu): !! ERROR COULD NOT FETCH WORK REQUEST EVENT: NULL...", __func__, pthread_self());

				SESNSTATUS_UNSET(instance_context.sesn_ptr->stat, SESNSTATUS_INSERVICE);

				//>>>>>>>>>>>>>>>>>>>>>>>
				SessionUnLockCtx (THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);//sesnptr wouldnt have changed as no processing took place
				//>>>>>>>>>>>>>>>>>>>>>>>
			}
		}
	}

}

#else

//
//	@brief at any one given moment in time the first worker thread to successfully hold lock will release iy (by pthreads)  upon invoking cond_wait
//	other threads who have previously been blocked on mutex_lock call will take turn in acquiring lock and blocking on cond
//	when the system have stabilised all worker threads will be waiting on cond in whatever order
//
//	If Session cannot be locked, read SocketMessage into message_queue_in
//
void *
ThreadWebSockets (void *ptr)

{
	unsigned 	counter=0,
						cmdid=0,
						handshake=1;
	long long service_start,
						service_end;
	Session 	*sesnptr=NULL;
	Socket 		*ssptr=NULL;
	SessionService *ss_ptr=NULL;
	HttpRequestContext http_request_context={0};
	RequestRateLimitStatus ratelimit_status={0};

	extern SessionsDelegator *const sessions_delegator_ptr;

	SessionsDelegator *const sd_ptr=sessions_delegator_ptr;
	Session *sesn_ptr_ipc=(Session *)ptr; //worker-delegator ipc pipe fds

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufSessnWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	__init_block:
	#if 1

	//setup key for storing the value of worker-delegator pipe Session *.
	//We may not need this key outside the context of this function, as the session is passed down from thread parent
	pthread_setspecific(THRKEY_WORKER_DELEGATOR_PIPE(sessions_delegator_ptr), (void *)sesn_ptr_ipc);

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		//makesure you initialise all keys in UFSRVThreadsOnceInitialiser (void);
		if (IS_PRESENT(InitialiseHttpRequestContext(&http_request_context, 0)))
		{
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_http_request_context_key, (void *)&http_request_context);//TODO: move key to delegator structure
		}
		else
		{
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit(-1);
		}

		syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Session Worker thread: '%lu'...", __func__, &http_request_context, pthread_self())
		;
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	InstrumentationBackend *instr_ptr=NULL;
	instr_ptr=InstrumentationBackendInit (NULL);//no namespace
	if (instr_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key, (void *)instr_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Session Worker thread: '%lu'...", __func__, pthread_self());
	}

	syslog(LOG_DEBUG, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Session Worker thread: '%lu'...", __func__, instr_ptr, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	PersistanceBackend *per_ptr=NULL;
	per_ptr=InitialisePersistanceBackend(NULL);
	if (per_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_data_key, (void *)per_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE persistence for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised Persistence Backend for Session Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		UserMessageCacheBackend *per_ptr_usrmsg=NULL;
		per_ptr_usrmsg=InitialiseCacheBackendUserMessage(NULL);
		if (per_ptr_usrmsg)
		{
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key, (void *)per_ptr_usrmsg);//TODO: move key to delegator structure
		}
		else
		{
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend UserMessage  for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit (-1);
		}

		syslog(LOG_INFO, "%s: SUCCESS (%p): Initialised Cache Backend UserMessage for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	FenceCacheBackend *per_ptr_fence=NULL;
	per_ptr_fence=InitialiseCacheBackendFence(NULL);
	if (per_ptr_fence)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_fence_key, (void *)per_ptr_fence);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend Fence  for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s (%p): SUCCESS: Initialised Cache Backend Fence for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	struct _h_connection *db_ptr=NULL;
	db_ptr=InitialiseDbBackend();
	if (db_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Session Worker thread: '%lu'...", __func__, pthread_self());


	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	MessageQueueBackend *mq_ptr=NULL;
	mq_ptr=InitialiseMessageQueueBackend(NULL);
	if (mq_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key, (void *)mq_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS Initialised MessageQueue Publisher backend for Session Worker thread: '%lu'...", __func__, pthread_self());

	#endif
	//end init_block

	while (1)
	{
		UFSRVResult res;
		SocketMessage *sm_ptr_consolidated=NULL;
		unsigned long stat_atomic=0;

		syslog(LOG_DEBUG, "%s (3 pid:'%lu): --------- START MAIN LOOP ------- ", __func__, pthread_self());

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu'): BEGIN COND_WAIT EVENT: Acquiring work queue mutex lock and fetching Session... I may block", __func__, pthread_self());
#endif

		if ((WorkQueueLock(sd_ptr, 0))!=0)
		{
			syslog(LOG_NOTICE, "%s (3:1>0 pid:'%lu): ERROR: COULD NOT ACQUIRE WORK QUEUE LOCK: looping gain.... ", __func__, pthread_self());
			continue;
		}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		while ((sd_ptr->sessions_work_queue.nEntries==0) && (sd_ptr->up_status==1))
		{
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "ThreadWebSockets (3:2 pid:'%lu' lock:30:-1 ): Mutex automatically released: Blocking on condition: waiting for signal: queue_not_empty_cond", pthread_self());
#endif
			pthread_cond_wait(&(sd_ptr->queue_not_empty_cond),	&(sd_ptr->work_queue_mutex));
		}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu): >>> RECIEVED WORK SIGNAL", __func__, pthread_self());
#endif

		//lock now acquired automatically by pthreads.. we unlock at the end

		if (sd_ptr->up_status==0)
		{
			syslog(LOG_INFO, "%s (3:4 pid:%lu): SessionDelegator is shutting down: releasing mutext lock: exiting...", __func__, pthread_self());

			WorkQueueUnLock(sd_ptr);
			pthread_exit(NULL);
		}


		//fetch_request_from_work_queue:

		//work_queue_mutex lock state: locked
		QueueEntry *qe_ptr=NULL;
		qe_ptr=deQueue(&(sd_ptr->sessions_work_queue));

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		if (sd_ptr->sessions_work_queue.nEntries==0)	pthread_cond_signal(&(sd_ptr->queue_empty_cond));//<<<<<<<

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		WorkQueueUnLock(sd_ptr);//other threads are now free to acquire the lock and dequeue further
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		sesnptr=(Session *)qe_ptr->whatever;
		free (qe_ptr);

		//we need this earlier
		sesnptr->persistance_backend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_data_key);
		UfsrvConfigRegisterUfsrverActivityWithSession (sesnptr, time(NULL));//TODO: consider using sesn_ptr->service_when_start_time

		__atomic_op:
		//if (__sync_and_and_fetch(&sesnptr->stat, SESNSTATUS_IOERROR))
		stat_atomic=__sync_add_and_fetch (&(sesnptr->stat), 0);
		if (SESNSTATUS_IS_SET(stat_atomic, SESNSTATUS_IOERROR))
		{
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN_OOB,
					__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN_OOB);

			//RemoveSessionToMonitoredWorkEvents(sesnptr);

			continue;
		}

		//>>>>>>>>>>>>>>>>>>>>>>>
		if ((SessionLockRW(sesnptr, 1))!=0)
		{
			_HandleBusySessionLock(sesnptr);
			continue;
		}
		//>>>>>>>>>>>>>>>>>>>>>>>

		//>>>>>>>> Session successfully locked

		//this is to trap a rare scenario where a session which is currently in recycler yet still in epoll's list
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_RECYCLED))
		{
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN,	__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLock (sesnptr);
			//>>>>>>>>>>>>>>>>>>>>>>>

			continue;
		}

		sesnptr->pid=pthread_self();

		__check_busy_session:
		#if 1

		//this can happen with long request queue and the session was terminated/suspended earlier
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_SUSPENDED ))
		{
			//TODO: We should fetch the message to disarm the event
			syslog(LOG_NOTICE, "%s (pid:%lu cid:%lu): RECEIVED EVENT FOR A SUSPENDED SESSION: NOT-SUSPENDING: UNLOCKING and RETURNING...",
					__func__, pthread_self(), SESSION_ID(sesnptr));

			{

				//>>>>>>>>>>>>>>>>>>>>>>>
				SessionUnLock (sesnptr);
				//>>>>>>>>>>>>>>>>>>>>>>>
			}

			//back to cond_wait
			continue;
		}

		//TODO: how did acquire the lock if the session is actively servicing?
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_INSERVICE ))
		{
			syslog(LOG_NOTICE, "%s (pid:%lu cid:%lu): RECEIVED EVENT for IN-SERVICE Session: (NOT) INSERTING in SocketMessageQueue (msg count='%lu')...",
				__func__, pthread_self(), sesnptr->session_id, sesnptr->message_queue_in.queue.nEntries);

			//statsd_inc(sesnptr->instrumentation_backend, "worker.in_event.serviced", 1.0);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLock (sesnptr);
			//>>>>>>>>>>>>>>>>>>>>>>>

			//back to cond_wait
			continue;
		}

		#endif
		//end check_busy_session

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		__session_in_service:

		//set the scene up... we need this as soon as possible, before we start queue consolidation, as Session context
		//needs to be setup prior to any request handling.
		__load_session_context:
		#if 1

		SESNSTATUS_SET(sesnptr->stat, SESNSTATUS_INSERVICE);//Session being picked up for service
		service_start=GetTimeNowInMicros();

		//sesnptr->persistance_backend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_data_key);
		sesnptr->instrumentation_backend	=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key);
		sesnptr->msgqueue_backend					=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key);
		sesnptr->usrmsg_cachebackend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key);
		sesnptr->fence_cachebackend				=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_fence_key);
		sesnptr->db_backend								=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_db_backend_key);

		#endif
		//end load_session_context

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu cid:%lu proto:'%d'): END COND_WAIT EVENT: Session retrieved: performing Session I/O work...",
				__func__, pthread_self(), SESSION_ID(sesnptr), PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesnptr))));
#endif

		//do work
		{
			unsigned long		session_id_invoked;
			Session 			*sesn_ptr_processed	= NULL;
			UFSRVResult 		*res_ptr;
			struct epoll_event	*ee_ptr=NULL;

			ee_ptr=(struct epoll_event *)sesnptr->event_descriptor;
			if (ee_ptr)
			{
				sesnptr->when_serviced_start=service_start/1000000UL;//time(NULL);

				session_id_invoked=SESSION_ID(sesnptr);

				//statsd_inc(sesnptr->instrumentation_backend, "worker_counter", 1.0);

				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
				//this may return a suspended session
				Session *sesn_ptr_aux;
				res_ptr=_HandleSessionWorkRequest (sesnptr, sd_ptr, session_id_invoked);//we always return session back regardless
				{
					sesn_ptr_aux=(Session *)res_ptr->result_user_data;

					if (unlikely(IS_EMPTY(sesn_ptr_aux)))
					{
						syslog(LOG_ERR, "%s (pid:%lu, cid_invoked:'%lu'): SEVERE ERROR: WE LOST REFERENCE TO SESSION...", __func__, pthread_self(), session_id_invoked);
						continue;
					}
				}
				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				SESNSTATUS_UNSET(sesn_ptr_aux->stat, SESNSTATUS_INSERVICE);

				//This does not always mean error: could be normal user-initiated shutdown so don't operate based on RESCODE_ERR
				//here we trap all the previous soft suspend operation: ie. socket no longer connected and shouldnot be in epoll, but some
				//may still linger in epoll
				bool recycle_flag=false;

				__session_suspended:
				#if 1

				//All error handling happens at lower level. Here we are only interested if the Session is still live or suspended
				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_SUSPENDED))
				{
					//two rules apply:
					//1) if _RESULT_TYPE_SUCCESS means user initiated quit, so we hard suspend
					//2)if _RESULT_TYPE_ERROR we check if protocol allow for grace soft period
					///syslog(LOG_ERR, LOGSTR_TSWORKER_HARD_SUSPEND,
						///__func__, pthread_self(), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), LOGCODE_TSWORKER_HARD_SUSPEND);

					if (_RESULT_TYPE_SUCCESS(res_ptr))
					{
						//all statements with '///' intentionally disabled
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					}
					else
					if ((_RESULT_TYPE_ERROR(res_ptr)) &&
						(!_PROTOCOL_CTL_RETAIN_SESSION_ON_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_aux))))))
					{
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					}
				}//SESNSTATUS_SUSPENDED

				#endif
				//end session_suspended

				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLEREQUEST))
				{
					WorkerDelegatorRaiseRecycleRequest	(sesn_ptr_aux, NULL);
					//TODO: unset SESNSTATU_RECYCLE if fail
				}

				#if 1
				{
					size_t queue_sz=0;

					//quick atomic check as we dont hold the socketmessage queue lock, other threads may still have logged something
					___atomic_check:
					if ((queue_sz=__sync_add_and_fetch (&(SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr_aux)), 0))>0)
					{
						syslog(LOG_DEBUG, LOGSTR_TSWORKER_QUEUE_POST_REQUEST,
								__func__, pthread_self(),sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), queue_sz, LOGCODE_TSWORKER_QUEUE_POST_REQUEST);

						WorkerDelegatorRaiseRecycleRequest	(sesn_ptr_aux, NULL);
					}
				}
				#endif

				//>>>>>>>>>>>>>>>>>>>>>>>
				service_end=GetTimeNowInMicros();
				sesn_ptr_aux->when_serviced_end=time(NULL);//service_end/1000000UL;
				statsd_timing(pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key), "worker.session.service.elapsed_time", (service_end-service_start));

				SessionUnLock (sesn_ptr_aux);

				//at the moment this semantic is disabled. Kicking off session in this loop has proved problematic
				//instead, we rely on timer thread to catch up with it
				if (recycle_flag)
				{
					//IMPORTANT to only add to recycler after session has been unlocked and completely reset
					SESNSTATUS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLED);

					RecyclerPut(1, (RecyclerClientData *)sesn_ptr_aux, (ContextData *)NULL, 0);
					recycle_flag=false;
				}
				//>>>>>>>>>>>>>>>>>>>>>>>

				//else the Session either destructed or suspended so we don't care
			}//epoll event
			else
			{
				syslog(LOG_ERR, "%s (pid:%lu): !! ERROR COULD NOT FETCH WORK REQUEST EVENT: NULL...",
					__func__, pthread_self());

				SESNSTATUS_UNSET(sesnptr->stat, SESNSTATUS_INSERVICE);

				//>>>>>>>>>>>>>>>>>>>>>>>
				SessionUnLock (sesnptr);//sesnptr wouldnt have change as no processing took place
				//>>>>>>>>>>>>>>>>>>>>>>>
			}

		}//block end

	}//while(1)

}

#endif

inline static void
_HandleBusySessionLock (InstanceHolderForSession *instance_sesn_ptr)
{
  Session *sesnptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//check if session is stuck
	//due to the semantics of ET we will get notification of readiness because we have not fetched data pending in the buffer
	if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_IOERROR)) {
		_LOGN(LOGSTR_TSWORKER_FAULTYSESN_COULDNTLOCK,	__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN_COULDNTLOCK);

		//we do this on error
		//RemoveSessionToMonitoredWorkEvents(sesnptr);

		return;
		//TODO: terminate session and force client to reauthenticate
	}

	//SESSION IS busy servicing or blocked: read back into main work events queue
	if ((sesnptr)&&(((struct epoll_event *)(sesnptr->event_descriptor))->events & EPOLLIN)) {
		//__concurrent_session_read:
		//we cannot check ratelimit status because we dont own the lock. had to be delegated to ufrvsowrker

		if (_PROTOCOL_CTL_READ_BLOCKED_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesnptr))))) {
			int return_value;

			//TODO: what if the session is not handshaked? don't read WS

			//__read_from_socket_into_msgqueue:
			if ((return_value = ReadFromSocket(instance_sesn_ptr, NULL,
					SOCKMSG_READSOCKET|SOCKMSG_DONTDECODE|SOCKMSG_DONTOWNSESNLOCK|SOCKMSG_KEEPMSGQUEUE_LOCKED)) <= 0) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', cid:'%lu', return_value:'%d', queue_size:'%lu'}: END COND_WAIT EVENT: Releasing mutex lock (-1): I/O error: Session request ignored...",\
					__func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesnptr), return_value, SESSION_INSOCKMSG_QUEUE_SIZE(sesnptr));

				//restore
				MessageQueueUnLock(sesnptr, &(sesnptr->message_queue_in));
				sesnptr->when_serviced_end = time(NULL);
				return;
			} else {
#if __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s (pid='%lu', o:'%p', cid='%lu'): END COND_WAIT EVENT: Releasing mutex lock (-1): Added to MessageQueue...", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
#endif
				//restore
				MessageQueueUnLock(sesnptr, &(sesnptr->message_queue_in));
				sesnptr->when_serviced_end = time(NULL);
			}

			//fall-through to continue below, back to the main loop. we may have read i/o error

			//end read_from_socket_into_msgqueue:
		} else {
			syslog(LOG_ERR, "%s (pid='%lu'. o:'%p', cid='%lu'): DID NOT READ INTO SocketMessage Queue: .._CTL_READ_BLOCKED_SESSION IS OFF", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
		}
		//end concurrent_session_read:
	} else if ((sesnptr)&&(((struct epoll_event *)(sesnptr->event_descriptor))->events & EPOLLOUT)) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: RECEIVED EPOLLOUT Event for a LOCKED SESSION: IGNORING...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesnptr, SESSION_ID(sesnptr));
	} else {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: RECEIVED UNKNOWN EPOLL Event for a LOCKED SESSION: IGNORING...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesnptr, SESSION_ID(sesnptr));
	}

	sesnptr->when_serviced_end = time(NULL);

	//finish cycle: back to cond_wait and attempt to deque again
}

/**
//@brief	called from the websocket worker thread after it picked up a session work request. Its main function is a glue between the worker and the
//	low-level network i/o message processing stream, including websocket de-framing and command processing.
//	after returning from the i/o stream it checks the incoming queue for missed messages.
*	@locks: SocketMessage Queue indirectly via ConsolidateMessageQueue
*/
static inline UFSRVResult *
_HandleSessionWorkRequest(InstanceContextForSession *instance_ctx_ptr, SessionsDelegator *sd_ptr, unsigned long session_id_invoked)
{
  UFSRVResult *res_ptr = _p_ProcessSessionSocketMessage(instance_ctx_ptr->instance_sesn_ptr, SESSION_INSOCKMSG_TRANS_PTR(instance_ctx_ptr->sesn_ptr), SOCKMSG_READSOCKET);

	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		if (res_ptr->result_code !=  RESCODE_IO_CONNECTIONCLOSED)  return (_HandleSuccessfulWorkRequest(sd_ptr, session_id_invoked, res_ptr));
		else return res_ptr;
	} else {
		//session maybe suspended or failed to Unsuspend
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:%lu, cid_invoked:'%lu'): UNSUCCESSFULLY PEROCESSED WORK REQUEST for Session...",__func__, pthread_self(), session_id_invoked);
#endif

		return res_ptr;// this contains the appropriate error descriptor
	}
}

/**
 * 	@brief Session request was previously successfully completed. Before we return to the thread's main loop we check if the
 * 	the session has received any new incoming packets and process accordingly.
 *
 * 	@locked sesn_ptr_processed: by main loop
 */
static inline UFSRVResult *
_HandleSuccessfulWorkRequest (SessionsDelegator *sd_ptr, unsigned long session_id_invoked, UFSRVResult *res_ptr)
{
	InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)_RESULT_USERDATA(res_ptr);//session object is always returned, even if suspended
  Session *sesn_ptr_processed = SessionOffInstanceHolder(instance_sesn_ptr_processed);
	if (SESSION_ID(sesn_ptr_processed) != session_id_invoked) {
#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu o:'%p' cid:%lu): SESSION CHANGE OVER: invoked with: '%lu' -> returned: '%lu'", __func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), session_id_invoked, SESSION_ID(sesn_ptr_processed));
#endif
	}

	//(2)check for/process stored message in incoming queue whilst in locked state
	//__consolidate_msgqueue_post:
	if (((struct epoll_event *)(sesn_ptr_processed->event_descriptor))->events & EPOLLIN) {
		//this locks the entire incoming queue. mid-process threads won't be able to add to it
		UFSRVResult		res;
		SocketMessage	*sm_ptr_consolidated;

		//consolidate all queue entries into the transient incoming SocketMessage buffer ie sesn_ptr->ssptr->incoming
		//LOCKS MESSAGE QUEUE
		ConsolidateSocketMessageQueue(sesn_ptr_processed, (SOCKMSG_CONSOLIDATE_INSESSION|SOCKMSG_LOCK_SOCKMSGQUEUE), &res);

		if (res.result_type == RESULT_TYPE_SUCCESS) {
			sm_ptr_consolidated = (SocketMessage *)res.result_user_data;

			if (!(sm_ptr_consolidated->sm_errno == 0)) {
				syslog(LOG_DEBUG, LOGSTR_QUEDIOERR, __func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), sm_ptr_consolidated->sm_errno, LOGCODE_TSWORKER_QUEUEDIOERR, "POST REQUEST SERVICE");

				//requires Session lock, but since we performed consolidation above, no SocketMessage queue lock is required
				//don't consolidate we are not passing SOCKMSG_CONSOLIDATE_INSESSION
				//BUFFERS(if any as result of consolidation) DEALLOCATED in hard suspend

				ErrorFromSocket (instance_sesn_ptr_processed, 0);//Suspends session

				res_ptr->result_type = RESULT_TYPE_ERR;
				res_ptr->result_code = RESCODE_IO_SOCKETQUEUE_CONSOLIDTED;
				res_ptr->result_user_data = instance_sesn_ptr_processed;

				goto request_error_pre;
			}

			res_ptr = _p_ProcessSessionSocketMessage(instance_sesn_ptr_processed, sm_ptr_consolidated, SOCKMSG_READBUFFER);
			if (_RESULT_TYPE_SUCCESS(res_ptr)) {
				goto request_successful;
			} else {
				//ON ERROR: _p_ProcessSessionSocketMessage() INVOKES SuspendsSession()
				goto request_error_pre; //this will return res_ptr along with its error settings
			}
		} else if ((res.result_code != RESCODE_LOGIC_EMPTY_RESOURCE) && (res.result_code != RESCODE_LOGIC_CANTLOCK)) {//ie error is not related to queue being empty
			//too bad we just bailout the session
			syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATION_ERR, __func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), LOGCODE_IO_BUF_CONSOLIDATION_ERR);

			res_ptr->result_type = res.result_type;
			res_ptr->result_code = res.result_code;
			res_ptr->result_user_data = sesn_ptr_processed;

			SuspendSession (instance_sesn_ptr_processed, SOFT_SUSPENSE);

			goto request_error_pre;
		}
		else goto request_successful;//queue was empty, so we are good to proceed
	}
	//end __consolidate_msgqueue_post

	request_successful:
	//sesn_ptr_processed->when_serviced_end=time(NULL);//orig sesnptr
	sesn_ptr_processed->persistance_backend = NULL;
	sesn_ptr_processed->instrumentation_backend = NULL;

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:%lu, cid:%lu): SUCCESSFULLY PEROCESSED WORK REQUEST...", __func__, pthread_self(), SESSION_ID(sesn_ptr_processed));
#endif

	_RETURN_RESULT_SESN(sesn_ptr_processed, instance_sesn_ptr_processed, RESULT_TYPE_SUCCESS, RESCODE_SERVICED)

	request_error_pre:
	//sesn_ptr_processed->when_serviced_end=time(NULL);//orig sesnptr
	goto request_error;

	request_error:
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:%lu, cid_invoked:'%lu'): UNSUCCESSFULLY PEROCESSED WORK REQUEST for Session...",__func__, pthread_self(), session_id_invoked);
#endif

	return res_ptr;

}

//https://firestuff.org/2016-02-24-down_the_epoll_rabbit_hole.html
/**
* @brief	process a single message contained in SocketMessage, which could be in any state other than new connection request (handled in the main loop).
 * Handshake and other regular comms are processed here.
* For brand new connections:
* Session is either newly created (FLEDGLING|CONNECTED) or a previously connected one (RECYCLED|CONNECTED)
* FLEDGLING does not have a SessionService body initiated. Where it fails handshake we destruct it as opposed to recycle
* For recurring requests Sesion must be (CONNECTED|HANDSKAED|AUTHENTICATED) RECYCLED is irrelevant
* we should not allow a Session to be serviced by two simultaneous workers
* @locks
*/
static UFSRVResult *
_p_ProcessSessionSocketMessage (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, int flag)
{
	extern SessionsDelegator	*const sessions_delegator_ptr;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	struct epoll_event *ee_ptr = (struct epoll_event *)sesn_ptr->event_descriptor;

	if ((ee_ptr->events&EPOLLRDHUP || ee_ptr->events&EPOLLERR|| ee_ptr->events&EPOLLHUP) && !(flag&SOCKMSG_READBUFFER)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_NOTICE, LOGSTR_TSWORKER_POLLERR,
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), LOGCODE_TSWORKER_POLLERR, "RETURNING, UNLESS EPOLLIN & EPOLLHUP are both set");
#endif

		if ((ee_ptr->events&EPOLLHUP /*|| ee_ptr->events&EPOLLRDHUP*/) && (ee_ptr->events&EPOLLIN)) {//not sure about EPOLLRDHUP
#ifdef __UF_FULLDEBUG
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_POLLERR_IN,
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), LOGCODE_TSWORKER_POLLERR_IN, "EPOLLIN & EPOLLHUP set: Performing one last read");
#endif

			goto __readable_input;
		}

		//requires session lock and SocketMessage lock
		ErrorFromSocket(instance_sesn_ptr, flag|=(SOCKMSG_CONSOLIDATE_INSESSION|SOCKMSG_LOCK_SOCKMSGQUEUE));

		//back to cond_wait
		_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_POLL)

		//TODO if SOCKMSG_READBUFFER is set, we should be able to finish off local processing in "offline" mode
	} else if (ee_ptr->events&EPOLLIN || flag&SOCKMSG_READBUFFER) {
		__readable_input:
		if (!(sesn_ptr->stat&SESNSTATUS_CONNECTED)) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu' fd:'%d'): SESSION NOT CONNECTED: RETURNING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));

			goto exit_non_successful;
		}

		if (_PROTOCOL_CLLBACKS_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
			//protocol_feature_handshake:
			if (!(sesn_ptr->stat&SESNSTATUS_HANDSHAKED) && !(sesn_ptr->stat&SESNSTATUS_AUTHENTICATED)) {
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', cid:'%lu'): INVOKING HANDSHAKE LIFECYCLE CALLBACK...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
				//protocol_callback:
				if (_PROTOCOL_CLLBACKS_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
					UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_HANDSHAKE_INVOKE(protocols_registry_ptr,
														PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
														instance_sesn_ptr, sock_msg_ptr, CALLFLAGS_EMPTY, NULL);

					switch (res_ptr->result_type)
					{
						case RESULT_TYPE_ERR:

							statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

							_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE)

						default:
							break;
							//just continue below with the _HandlePostSuccessfulIncomingHandshake()
					}
				}
				//end protocol_callback

				return (_HandlePostSuccessfulIncomingHandshake(instance_sesn_ptr, sock_msg_ptr));

			} else if ((sesn_ptr->stat&SESNSTATUS_HANDSHAKED) && (sesn_ptr->stat&SESNSTATUS_AUTHENTICATED)) {
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): CONNECTED USER MSG RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

				//if (IsRateLimitExceededForSession (sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), RLNS_REQUESTS))	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_USER_RATELIMIT_EXCEEDED);

				return(_HandleMessageForConnectedSession(instance_sesn_ptr, sock_msg_ptr, flag));
			} else {
				//in a level triggered polling, an event could be in the queue for a session that is recycled because the object is not
				//destroyed it is in the recycler.
				syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p' cid:'%lu'): INCONSISTENT SESSION STATE: ('%lu'): IGNORING", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sesn_ptr->stat);

				//TODO: this is causes inconsistencies, especially if ses is already suspended
				//SuspendSession (sesn_ptr, 0);

				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_SESSIONSTATE)
			}
			//end protocol_feature_handshake
		} else {
			//protocol_feature_no_handshake:
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' fd:'%d'): NO-HANDSHAKE CONNECTED USER MSG RECEIVED...", __func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));
#endif
			//this is too early to identify the user
			//if (IsRateLimitExceededForSession (sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), RLNS_REQUESTS))	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_USER_RATELIMIT_EXCEEDED);

			return (_HandleMessageForConnectedSession(instance_sesn_ptr, sock_msg_ptr, flag));
		}
	} else if (ee_ptr->events & EPOLLOUT) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' fd:'%d'): Received  EPOLLOUT event: DEQUEUEING outgoing SocketMessage Queue...", __func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));
#endif
		return (_InvokeLifecycleCallbackMsgOut(instance_sesn_ptr, sock_msg_ptr, CALLFLAGS_EMPTY));
	}

	exit_non_successful:
	_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_POLL)

}

static inline UFSRVResult *
_InvokeLifecycleCallbackPostHandshake (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (_PROTOCOL_CLLBACKS_POST_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_POST_HANDSHAKE_INVOKE(protocols_registry_ptr,
                                                                    PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
                                                                    instance_sesn_ptr, sock_msg_ptr, CALLFLAGS_EMPTY);

		switch (_RESULT_TYPE(res_ptr))
		{
			case RESULT_TYPE_ERR:

        statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

				SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);

				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE)

			default:
				//could have fallen through to _exit_sucess: below
				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_AUTHENTICATION)
		}
	}

	exit_success:
	_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_AUTHENTICATION)
}

static inline UFSRVResult *
_InvokeLifecycleCallbackMsgOut (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	DispatchSocketMessageQueue (instance_sesn_ptr, sesn_ptr->message_queue_out.queue.nEntries);

	if (_PROTOCOL_CLLBACKS_MSG_OUT(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_MSG_OUT_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											instance_sesn_ptr, sock_msg_ptr, call_flags, 0);

		switch (_RESULT_TYPE(res_ptr))
		{
			case RESULT_TYPE_ERR:

        statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

				SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);

				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MSGDISPATCHED)

			default:
				//could have fallen through to _exit_sucess: below
				if (_RESULT_CODE_EQUAL(res_ptr, RESULT_CODE_SESN_SOFTSPENDED))	SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);
				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGDISPATCHED)
		}
	} else {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO MSG OUT CALLBACK DEFINED FOR PROTOCOL (id:'%d', name:'%s')", __func__, pthread_self(), SESSION_ID(sesn_ptr),
						PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))), PROTO_PROTOCOL_NAME(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));
#endif
	}

	exit_success:
	_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGDISPATCHED)
}

/**
 * 	@brief: Key Session routing function for connections that support handshake.
 * 	Transition the newly connected session (aka in transient state) past initial incoming handshake.
 * 	Session is not authenticated in anyway. We have just processed basic comms/protocol semantics.
 *
 * 	@dynamic_memory redisReply: IMPORTED BY PROXY <- BackendCacheGetSessionRecordByCookie() AND EXPORTED -> _AuthenticateForBackendCookieHashedSession().
 * 	  Not feree'd here
 */
inline static UFSRVResult *
_HandlePostSuccessfulIncomingHandshake (InstanceHolderForSession *instance_sesn_ptr_transient, SocketMessage *sock_msg_ptr)
{
  Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

  SESNSTATUS_SET(sesn_ptr_transient->stat, SESNSTATUS_TRANSIENT);

  InstanceHolderForSession *instance_sesn_ptr_hashed = (InstanceHolderForSession *)HashLookup(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)SESSION_COOKIE(sesn_ptr_transient), true);

	//this may indicate a concurrent sign on
	if (IS_PRESENT(instance_sesn_ptr_hashed)) {
    UFSRVResult *res_ptr_cookie = AuthenticateForCookieHashedSession(instance_sesn_ptr_transient, instance_sesn_ptr_hashed, sock_msg_ptr);

		if (_RESULT_TYPE_SUCCESS(res_ptr_cookie)) {
			InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)_RESULT_USERDATA(res_ptr_cookie);
			return (_InvokeLifecycleCallbackPostHandshake(instance_sesn_ptr_processed, sock_msg_ptr));
		} else if ((_RESULT_TYPE_ERROR(res_ptr_cookie)) && (_RESULT_CODE_EQUAL(res_ptr_cookie, RESCODE_USER_SESN_KILLED))) {
			//falls through to new session block below: recreate session, as hash was invalid
		} else {
		  return	res_ptr_cookie;//user not allowed through
		}
	} else {
#ifdef __UF_TESTING
	  syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND SESSION IN LOCAL COOKIE HASH: TRYING BACKEND CACHE...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient));
#endif

		//in combination with TRANSIENT status this will help trap concurrent sign on attempts with the same cookie in the conditional above. cleared downstream
		if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient))) {
			_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

    CacheBackendGetRawSessionRecordByCookie(SESSION_COOKIE(sesn_ptr_transient), CALLFLAGS_EMPTY);

		if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) { /*important to check for RESCODE_BACKEND_DATA*/
			UFSRVResult *res_ptr_backend = NULL;
			//user has a valid cookie even though not known locally to this instance: this server could have rebooted, or user coming from another server
			res_ptr_backend = AuthenticateForBackendCookieHashedSession(instance_sesn_ptr_transient, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), sock_msg_ptr);

			if (_RESULT_TYPE_SUCCESS(res_ptr_backend)) {
				InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)_RESULT_USERDATA(res_ptr_backend);
				return (_InvokeLifecycleCallbackPostHandshake (instance_sesn_ptr_processed, sock_msg_ptr));
			} else {
				return res_ptr_backend; //user not allowed through
			}
		}

		//falls through below to new session, as we couldn't find the user on the backend cache with this cookie
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND SESSION IN LOCAL OR BACKEND CACHE: proceeding with New Session Initialisation: Session may still be discoverable in DB BACKEND with this cookie", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient));
#endif

  UFSRVResult *res_ptr_new_session = NULL;

  //user still has cookie that is not recorded on the backend cache and not known locally: could be new registration,
  //or user directed to re-authenticate with new cookie. At any rate, the db backend will be the ultimate source
  res_ptr_new_session = AuthenticateForNonCookieHashedSession(instance_sesn_ptr_transient);

  if (_RESULT_TYPE_SUCCESS(res_ptr_new_session)) {
    InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)_RESULT_USERDATA(res_ptr_new_session);
    return _InvokeLifecycleCallbackPostHandshake (instance_sesn_ptr_processed, sock_msg_ptr);
  }

  return res_ptr_new_session; //contains error of sorts
}

static inline UFSRVResult *
_HandleMessageForConnectedSession (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, int flag)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (_PROTOCOL_CLLBACKS_MSG(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_MSG_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											instance_sesn_ptr, sock_msg_ptr, flag, 0);

		switch (res_ptr->result_type)
		{
		  case RESULT_TYPE_ERR:
			case RESULT_TYPE_PROTOCOLERR:
			case RESULT_TYPE_IOERR:

				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, res_ptr->result_code)

			default:
				//reset buffer
				if (sock_msg_ptr->processed_msg_size > 0) {
					free (sock_msg_ptr->_processed_msg);
					sock_msg_ptr->_processed_msg = 0;
					sock_msg_ptr->processed_msg_size = 0;
				}

				_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, res_ptr->result_code)
		}
	} else {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO MSG CALLBACK DEFINED FOR PROTOCOL (id:'%d', name:'%s')", __func__, pthread_self(), SESSION_ID(sesn_ptr),
				PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))), PROTO_PROTOCOL_NAME(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));
#endif
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}
