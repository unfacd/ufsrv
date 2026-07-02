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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <sessions_delegator_type.h>
#include <thread_context_sfu_type.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include <ufsrvrest/include/protocol_http.h>
#include <delegator_sfu_listener_thread.h>
#include <ufsrv_core/jobworkers/user_callback_job.h>
#include <stun_agent/stun_agent.h>
#include <ufsrvmsg_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <uflib/scheduled_jobs/scheduled_jobs_type.h>
#include <ufsrv_core/jobworkers/jobworkers_utils.h>
#include <jobworkers/base_thread_context_data_type.h>
#include "delegator_sfu_worker_thread.h"
#include "sfu_session_provider.h"
#include <session_worker_sfu_thread.h>
#include <uflib/recycler/recycler.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <session.h>

extern ufsrv							*const masterptr;
extern const Protocol			*const protocols_registry_ptr;
extern __thread ThreadContext      ufsrv_thread_context;

static WorkerPoolDescriptor *const _GetUfsrvWorkerPoolDescriptor(oneoff_initialiser on_created);
static void _InitialiseUfsrvSfuScheduledJobsTypes(void);
static void _LaunchUfsrvWorkers(void);
static UFSRVResult *_UfsrvWorkersThreadSfuDataContextInitialiser(BaseThreadContext *thread_base_ctx_data);

ScheduledJobs  *const _GetScheduledJobsStore(void);

ScheduledJobs  *const
_GetScheduledJobsStore(void)
{
  static ScheduledJobs scheduled_jobs_store;
  return &scheduled_jobs_store;
}


static UFSRVResult *
_UfsrvWorkerPoolOneoffInitialiser(WorkerPoolDescriptor *pool_descriptor)
{
  return DefaultUfsrvWorkerPoolOneoffInitialiser(pool_descriptor);
}

static WorkerPoolDescriptor *const
_GetUfsrvWorkerPoolDescriptor(oneoff_initialiser on_created) {
  static WorkerPoolDescriptor ufsrvworker_pool;

  ufsrvworker_pool.on_created = on_created;

  return &ufsrvworker_pool;
}

/**
 * @brief Initialise and launch the job workers subsystem (one per instance)
 */
static void
_LaunchUfsrvWorkers()
{
  WorkerPoolDescriptor *const pool_descriptor = _GetUfsrvWorkerPoolDescriptor(_UfsrvWorkerPoolOneoffInitialiser);
  size_t pool_sz = GetJobWorkersPoolSize(_CONFIGDEFAULT_MAX_UFSRV_WORKERS);

  pool_descriptor->workers_pool_config_descriptor.up_status = POOL_STATE_UP;
  pool_descriptor->workers_pool_config_descriptor.pool_sz = pool_sz;
  pool_descriptor->thread_handlers.on_instantiated = _UfsrvWorkersThreadSfuDataContextInitialiser;
  RegisterJobWorkersConfigurationDescriptorForSfu(&pool_descriptor->workers_pool_config_descriptor);

  if (IS_PRESENT(pool_descriptor->on_created)) {
    pool_descriptor->on_created(pool_descriptor);
  }

  LaunchUfServerWorkerThreads(pool_descriptor, sizeof(ThreadContextSfu));
}

/**
 * @brief Callback initialiser for UfsrvWorker threads for ufsrvsfu class servers. Called inside the UfsrvWorkerThread.
 * @param thread_base_ctx_data
 */
static UFSRVResult *
_UfsrvWorkersThreadSfuDataContextInitialiser(BaseThreadContext *thread_base_ctx_data)
{
  ThreadContextSfu *thread_context_sfu = thread_base_ctx_data->user_thread_context;

  WorkersConfigDescriptor *config_descriptor = &(thread_base_ctx_data->pool_descriptor->workers_pool_config_descriptor);

  //todo: this is the old pthread_key based implementation. Delete one the thread_local implementation is finalised.
  pthread_setspecific(config_descriptor->ufsrv_thread_context_key, (void *)&thread_context_sfu);

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  InstrumentationBackend *instr_ptr = InstrumentationBackendInit(NULL, &(thread_context_sfu->instrumentation_backend));//no namespace
  if (IS_PRESENT(instr_ptr)) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_setspecific(config_descriptor->ufsrv_instrumentation_backend_key, (void *)instr_ptr);

    ufsrv_thread_context.instrumentation_backend = instr_ptr;//TBD
  } else {
    syslog(LOG_NOTICE, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
  }

  syslog(LOG_INFO, "%s: SUCCESS (base_th_context:'%p', instrum_ptr:'%p'): Initialised Instrumentation Backend for Ufsrv Worker thread: '%lu' (NOT IMPLEMENTED)...", __func__, thread_base_ctx_data, instr_ptr, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  struct _h_connection *db_ptr = InitialiseDbBackend();
  if (db_ptr) {
    //todo: to be removed once thread_local implementation below is complete
    pthread_setspecific(config_descriptor->ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure

    thread_context_sfu->db_backend = db_ptr;
    ufsrv_thread_context.db_backend = db_ptr;//TBD
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//    _exit(-1);
  }

  syslog(LOG_INFO, "%s: SUCCESS (base_th_context:'%p', db_backend:'%p'): Initialised DB Backend for Ufsrv Worker thread: '%lu'...", __func__, thread_base_ctx_data, db_ptr, pthread_self());

  //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  syslog(LOG_INFO, "%s: SUCCESS: Initialised MessageQueue Publisher Backend for UfServerWorker thread: '%lu'...", __func__, pthread_self());

  _RETURN_RESULT_RES(&(thread_base_ctx_data->ufsrv_result), NULL, RESULT_TYPE_SUCCESS, RECODE_NONE)
}

static void
_InitialiseUfsrvSfuScheduledJobsTypes(void)
{
  //TODO implementation is is too ufsrvwebsock/api specific -> re-implement for sfu
//  InitialiseScheduledJobTypeForSessionsTimeouts();
}

/**
 *  @brief: One-off Protocol type data initialisation
 */
UFSRVResult *
proto_sfu_init_callback(Protocol *proto_ptr)
{
  syslog(LOG_INFO, "%s: Initialising protocol: '%s' ...", __func__, proto_ptr->protocol_name);

  UfsrvSessionsDelegator *sd_ptr = InitialiseWorkerDelegator();
  if (IS_EMPTY(sd_ptr)) {
    syslog(LOG_ERR, "%s: ERROR COULD NOT INITIALISE DELEGATOR... EXISTING", __func__ );
    exit(-1);
  }

  InitUFSRVForSfu(sd_ptr);

  LaunchConnectionListenerThreads(sd_ptr);//see commented out thread launching code below
  LaunchSessionWorkerThreadsSfu(sd_ptr);

  _LaunchUfsrvWorkers();
  LaunchTimerManagerThread(&_InitialiseUfsrvSfuScheduledJobsTypes);
  LaunchSessionsSfuDelegatorThread();

  {
    //initialise aux MessgeQueueBackend object for non-session worker use
    syslog(LOG_INFO, "%s: Building connection handle for MessageQueue Backend...", __func__);
    __unused MessageQueueBackend *msgq_ptr = NULL;
    msgq_ptr = BuildConnectionHandleForMessageQueueBackend(NULL);
//    if (msgq_ptr) {
//      sd_ptr->msgqueue_pub_ptr = msgq_ptr;
//    } else {
//      syslog(LOG_INFO, "%s: ERROR: COULD NOT INITIALISE Auxiliary MessageQueueBackend for Session Delegator thread", __func__);
//      sd_ptr->msgqueue_pub_ptr = NULL;
//    }
  }

  //Not applicable
	/*sessions_delegator_ptr->session_worker_ths = malloc(sizeof(pthread_t) * sessions_delegator_ptr->setsize);

	for (size_t i=0; i<sessions_delegator_ptr->setsize; i++) {
		int result = pthread_create(&(sessions_delegator_ptr->session_worker_ths[i]), NULL,
                                ThreadSfuConnectionListenerWorker, (void *) NULL);
		if (result != 0) {
			syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%lu'): terminating...", __func__, sessions_delegator_ptr->setsize, i);
			exit (-1);
		}
	}*/

#if 0
	Protocol *proto_ptr_my;
	ProtocolHttp *proto_http_ptr;

	//_GET_PROTO_HTTP(proto_ptr);
	proto_ptr_my = ProtocolGet (PROTOCOLID_HTTP);
	proto_http_ptr = calloc(1, sizeof(ProtocolHttp));
	_ASSIGN_PROTOCOL_TYPE_DATA(proto_ptr_my, proto_http_ptr);//connect the two pointers


	//AA+ HTTP
	syslog(LOG_INFO, "%s: ASSIGNED DEFAULT HTTP URL AND ERROR HANDLERS...", __func__);

	proto_http_ptr->http_handlers.internal_error_handler = onion_handler_new((onion_handler_handler)onion_default_error, NULL, NULL);

	proto_http_ptr->http_handlers.root_handler = (onion_handler *)onion_root_url();

	proto_http_ptr->constants.max_post_size = 1024*1024; // 1MB
	proto_http_ptr->constants.max_file_size = 1024*1024*1024; // 1GB


	//HTTP_PROTOCOL_MAXPOSTSIZE(protocols_registry_ptr);

	InitUfsrvApiEndpoints();
	proto_http_ptr->http_handlers.root_auth_handler=onion_handler_auth_pam("ufsrv api", NULL, proto_http_ptr->http_handlers.root_handler);

	InitAttachmentDescriptorRecyclerTypePool();
	InitialiseAttachmentsHashTable ();
	InitialiseBasicAuthLruCache ();

	RegisterFenceUserPreferencesSource ();
	RegisterUserPreferencesSource ();
#endif

	return _ufsrv_result_generic_success;
}


/**
 * 	@brief: we don't perform a stand-alone main listener role. see main protocol_init function, which launches its own listener-workers
 */
UFSRVResult *
proto_sfu_init_listener (void)
{

	return _ufsrv_result_generic_success;

}

UFSRVResult *
proto_sfu_main_listener_callback (Socket *sock_ptr_listener, ClientContextData *context_ptr)
{
	return _ufsrv_result_generic_success;
}

/**
 * @brief: Lifecycle callback for when a new session is being generated.
 *
 * @param call_flag: if set indicates the object is from recycler origini so it should only require light
 * setup
 *
 */
UFSRVResult *
proto_sfu_init_session_callback (Session *sesn_ptr, __unused unsigned callflags)
{
#if 0

	HttpSession *http_ptr;

	if (callflags==0)//brand new, heap based instance
	{

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (cid:'%lu): INITIALISING NEW HTTP SESSION UNDER HOST APP SESSION: '%lu'...", __func__,
				SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr));
#endif

		http_ptr=calloc(1, sizeof(HttpSession));

		//SESSION_HTTP_REQUEST(sesn_ptr)->headers=onion_dict_new();
		//onion_dict_set_flags(SESSION_HTTP_REQUEST(sesn_ptr)->headers, OD_ICASE);
		//HTTPSESN_REQUEST(http_ptr).headers=onion_dict_new();
		//these are common for both at this stage. TODO: look for optimisation
		//onion_dict_set_flags(HTTPSESN_REQUEST(http_ptr).headers, OD_ICASE);

		SESSION_PROTOCOLSESSION(sesn_ptr)=(ProtocolSessionData *)http_ptr;

	}
	else
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (cid:'%lu): INITIALISING RECYCLER HTTP SESSION UNDER HOST APP SESSION: '%lu'...", __func__,
				SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr));
#endif

		http_ptr=calloc(1, sizeof(HttpSession));
		SESSION_PROTOCOLSESSION(sesn_ptr)=(ProtocolSessionData *)http_ptr;

		//TODO: at the moment the session object needs to be recreated regardless of recycler origin. Future optimisation
		//this is done is SuspendSession() as an overriding behaviour
		//existing instance we just prime request again with new allocation
		//http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	}

	common_init:
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED);
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_AUTHENTICATED);
	SESSION_SOCKETBLOCKSZ(sesn_ptr)=masterptr->buffer_size;//set default read block size

	HTTPSESN_REQUEST(http_ptr).headers=onion_dict_new();
	onion_dict_set_flags(HTTPSESN_REQUEST(http_ptr).headers, OD_ICASE);
	HTTPSESN_SESSIONID(http_ptr)=SESSION_ID(sesn_ptr);

#endif

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	//__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

/**
 *
 *	@brief: This is invoked as just before session's socket is closed. Following this call
 *	object will be marshaled into recycler.
 *	Currently, This is called from SuspendSession(0 which frees the HttpSession *.
 */
UFSRVResult *
proto_sfu_reset_session_callback (Session *sesn_ptr, __unused unsigned callflags)
{
#if 0
	HttpSession *http_ptr;
	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (callflags==0)
	{
		//soft reset
	}
	else
	{
		if (http_ptr)
		{
			syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP SESSION: PUSHING TO RECYCLER...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));

			onion_request_free(HTTPSESN_REQUEST_PTR(http_ptr));
			//onion_response_free(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr));//AA-
			onion_response_destruct(sesn_ptr);//A+

			//release json object
			if (HTTPSESN_JSONDATA(http_ptr))
			{
				json_object_put(HTTPSESN_JSONDATA(http_ptr));
				HTTPSESN_JSONDATA(http_ptr)=NULL;
			}

			if (SESSION_PROTOCOLSESSION(sesn_ptr))
			{
				free(SESSION_PROTOCOLSESSION(sesn_ptr));
				SESSION_PROTOCOLSESSION(sesn_ptr)=NULL;
			}
		}
	}
#endif

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
}

/**
 *
 * @param sesn_ptr Session created by the listener-worker thread. Don't use.
 * @param sm_ptr
 * @param callflags
 * @param comeback
 * @return
 */
UFSRVResult *
proto_stun_hanshake_callback(InstanceHolderForSession *instance_holder, __unused SocketMessage *sm_ptr, unsigned __unused callflags, __unused int **comeback)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_holder);

  //No session created at this stage for SFU

  //QueueInUserCallBackJob(BuildICEAgentJob(NULL)); //this path is using UfsrvWorker thread. Not used.

  InstanceHolderForSfuSession *instance_session_new = (InstanceHolderForSfuSession *)RecyclerGet(SfuSessionPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
  if (IS_PRESENT(instance_session_new)) {
    UserCallbackJobDescriptor *job_descriptor = BuildICEAgentJob(NULL, instance_session_new);
    job_descriptor->handler(job_descriptor->callback_args, instance_session_new);

    SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);
  } else {
    SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MEMORY_EXHAUSTED);
  }

}

UFSRVResult *
proto_stun_post_hanshake_callback(__unused InstanceHolder *instance_holder)
{
	return 0;
 
}

/**
 *  Handler returns the following:
 *  Procesed: the request was matched and processed -> connection will be closed
 *  KeepAlive: PROCESSED AND we we want to retain the connected for more future data
 *  NOT PROCESSED we terminate
 */
UFSRVResult *
proto_sfu_msg_callback(InstanceHolderForSession *instance_session, SocketMessage *sock_msg_ptr, __unused unsigned frame_offset, __unused size_t len)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_session);
  if (IS_PRESENT(sesn_ptr->io_event_handlers.on_read)) {
    sesn_ptr->io_event_handlers.on_read(instance_session, PRE_HANDLER);
  }
	return _ufsrv_result_generic_success;

#if 0
	ssize_t amount_read;
	int rescode;

	if ((amount_read=ReadFromSocket(sesn_ptr, sock_msg_ptr, frame_offset/*as flag*/))>0)
	{
		onion_connection_status st=onion_request_write(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr), (const char *)sock_msg_ptr->_processed_msg/*buffer*/, sock_msg_ptr->processed_msg_size/* len*/);

		if (st!=OCS_NEED_MORE_DATA)
		{
			//the request was logically complete (e.g. complete file, or etc..)
			if (st==OCS_REQUEST_READY)
			{
				//invoke handlers
				st=onion_request_process(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)); // May give error to the connection, or yield or whatever.
				if (st==OCS_CLOSE_CONNECTION)
				{
					//success case singular connection
					rescode=	RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				}
				else
				if(st==OCS_KEEP_ALIVE)
				{
					rescode=RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP KEEPALIVE CONNECTION: WON'T TERMINATE CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));
					goto protocol_exit;
				}
				else
				{
					rescode=RESCODE_PROG_NULL_POINTER;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: UNKNOWN HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				}

			}//OCS_REQUEST_READY

			protocol_exit_terminal:
			SuspendSession (sesn_ptr, 0);

			protocol_exit:
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);
		}
		else
		{
			syslog(LOG_DEBUG, "%s (cid:'%lu'): HTTP HANDLER RETURNED 'OCS_NEED_MORE_DATA': WON'T TERMINATE CONNECTION...", __func__, SESSION_ID(sesn_ptr));
			goto fragmented_data;
		}

	}
	else
	if (amount_read==0)//if we are reading a very large frame, the first fragment will be seen by decode_hybi, which will return 0
		//subsequent reads will detect missing size and will continue to report zero until  full frame is recieved up to 65k which is the max frame zize we allowe for Websocket
	{
		fragmented_data:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', rvbytes:'%lu', raw_msg_sz:'%lu' upload_sz:'%lu'}: COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED:  RETURNING...",
				__func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_CUMMULATIVE_RC(sesn_ptr), sock_msg_ptr->raw_msg_size, HTTPProtoGetCurrentFileSize(SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)));

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION);
	}
	else
	{
		read_error:
		switch (amount_read)
		{
		case -1:
			rescode=RESCODE_IO_CONNECTIONCLOSED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspended

		case -2:
			rescode=RESCODE_LOGIC_CANTLOCK;	break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK);

		case -3://user sent termination in WS
			rescode=RESCODE_IO_CONNECTIONCLOSED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);

		case -4:
			rescode=RESCODE_IO_DECODED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_DECODED);//this fatal couldent base64 decode: suspend

		case -5:
			rescode=RESCODE_IO_MISSGINGFRAMEDATA;	break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MISSGINGFRAMEDATA);//benign error couldn't process frame because of incomplete frame data

		default:
			rescode=RESCODE_PROG_NULL_POINTER;
			//_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}
	}


	exit_error:

	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
#endif

}

UFSRVResult *
proto_sfu_msg_out_callback (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
#if 0
	ssize_t amount_read;
	int rescode;
	int 						fd			=SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd;
	/*if (fd<=0)
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FILEFD IS CLOSED: Suspending session...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

		SuspendSession (sesn_ptr, 0);
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}
	else*/
	if (fd>0)
	{
			switch (HttpSendFile(sesn_ptr))
			{
				case OCS_NEED_MORE_DATA:
#ifdef __UF_TESTING
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): HTTP HANDLER RETURNED 'OCS_NEED_MORE_DATA': WON'T TERMINATE CONNECTION...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION);

				case OCS_PROCESSED:
					SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd=0;
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_SESN_SOFTSPENDED);//ask to suspend session

				case OCS_NOT_PROCESSED:
				case OCS_INTERNAL_ERROR:
				default:
					//upstream SuspendSession (sesn_ptr, 0);
					SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd=0;
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
			}
	}

#if 0
	if ((amount_read=ReadFromSocket(sesn_ptr, sock_msg_ptr, frame_offset/*as flag*/))>0)
	{
		onion_connection_status st=onion_request_write(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr), (const char *)sock_msg_ptr->_processed_msg/*buffer*/, sock_msg_ptr->processed_msg_size/* len*/);

		if (st!=OCS_NEED_MORE_DATA)
		{
			//the request was logically complete (e.g. complete file, or etc..)
			if (st==OCS_REQUEST_READY)
			{
				st=onion_request_process(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)); // May give error to the connection, or yield or whatever.
				if (st==OCS_CLOSE_CONNECTION)
				{
					//success case singular connection
					rescode=	RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				}
				else
				if(st==OCS_KEEP_ALIVE)
				{
					rescode=RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP KEEPALIVE CONNECTION: WON'T TERMINATE CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));
					goto protocol_exit;
				}
				else
				{
					rescode=RESCODE_PROG_NULL_POINTER;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: UNKNOWN HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				}

			}//OCS_REQUEST_READY

			protocol_exit_terminal:
			SuspendSession (sesn_ptr, 0);

			protocol_exit:
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);
		}
		else
		{
			syslog(LOG_DEBUG, "%s (cid:'%lu'): HTTP HANDLER RETURNED 'OCS_NEED_MORE_DATA': WON'T TERMINATE CONNECTION...", __func__, SESSION_ID(sesn_ptr));
			goto fragmented_data;
		}

	}
	else
	if (amount_read==0)//if we are reading a very large frame, the first fragment will be seen by decode_hybi, which will return 0
		//subsequent reads will detect missing size and will continue to report zero until  full frame is recieved up to 65k which is the max frame zize we allowe for Websocket
	{
		fragmented_data:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', rvbytes:'%lu', raw_msg_sz:'%lu' upload_sz:'%lu'}: COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED:  RETURNING...",
				__func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_CUMMULATIVE_RC(sesn_ptr), sock_msg_ptr->raw_msg_size, HTTPProtoGetCurrentFileSize(SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)));

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION);
	}
	else
	{
		read_error:
		switch (amount_read)
		{
		case -1:
			rescode=RESCODE_IO_CONNECTIONCLOSED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspended

		case -2:
			rescode=RESCODE_LOGIC_CANTLOCK;	break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK);

		case -3://user sent termination in WS
			rescode=RESCODE_IO_CONNECTIONCLOSED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);

		case -4:
			rescode=RESCODE_IO_DECODED; break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_DECODED);//this fatal couldent base64 decode: suspend

		case -5:
			rescode=RESCODE_IO_MISSGINGFRAMEDATA;	break;
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MISSGINGFRAMEDATA);//benign error couldn't process frame because of incomplete frame data

		default:
			rescode=RESCODE_PROG_NULL_POINTER;
			//_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}
	}


	exit_error:
	//NO DON'T: this is done in ReadSocket on read() <0
	//SuspendSession (sesn_ptr, 0);

#endif
#endif

	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

UFSRVResult *
proto_sfu_service_timeout_callback (Session *sesn_ptr, time_t now, unsigned long call_flags)
{
#if 0
	bool recycle_flag	=	false;
	bool suspended_flag	=	false;

	if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED) || !SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED))
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: CHECKING for Dangling Session with incomplete handshake (timeout='%u')...",
			__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.unauthenticated);
#endif
		//incomplete handshake
		if ((sessions_delegator_ptr->user_timeouts.unauthenticated>0)&&
			(now-sesn_ptr->when_serviced_end)>sessions_delegator_ptr->user_timeouts.unauthenticated)
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: FOUND Dangling Session: RECYCLING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			if (SuspendThisSession (NULL, sesn_ptr, 1))
			{
				recycle_flag=true;
			}
		}
	}
	else
	if  (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED) && SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED))
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Connected-Idling Session (timeout='%u')...",
			__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.connected, SESSION_ID(sesn_ptr));
#endif
		if ((sessions_delegator_ptr->user_timeouts.connected>0)&&
			(now-sesn_ptr->when_serviced_end)>sessions_delegator_ptr->user_timeouts.connected)
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', now:'%lu', end_time:'%lu', now2:'%lu'): FOUND Connected Idling Session: SUSPENDING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), now, sesn_ptr->when_serviced_end, time(NULL));

			SuspendThisSession (NULL, sesn_ptr, 0);	suspended_flag=true;
		}
		else
		if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_LOCATED))
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): CHECKING for LOCATION-LESS Session (timeout='%u'): 'cid='%lu'...",
				__func__, pthread_self(), sessions_delegator_ptr->user_timeouts.locationless, sesn_ptr->session_id);
#endif
			if ((sessions_delegator_ptr->user_timeouts.locationless>0)&&
				(now-sesn_ptr->when_serviced_end)>sessions_delegator_ptr->user_timeouts.locationless)
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND Connected-Location-less Session: SUSPENDING...",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

				SuspendThisSession (NULL, sesn_ptr, 0); suspended_flag=true;
			}
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): UNABLE TO ASCERTAIN THE STATE OF A CONNECTED SESSION: Forcibly suspending...",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			SuspendThisSession (NULL, sesn_ptr, 0); suspended_flag=true;
		}

	}
	else
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED) && (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE)))
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Suspended Session (timeout:'%u'): 'cid='%lu'...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.suspended);
#endif
		if ((sessions_delegator_ptr->user_timeouts.suspended>0)&&
			(now-sesn_ptr->when_serviced_end)>sessions_delegator_ptr->user_timeouts.suspended)
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND Suspended Idling Session: RECYCLING: ...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			if (SuspendThisSession (NULL, sesn_ptr, 1))
			{
				recycle_flag=true;
			}
		}
	}
	else
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))
	{
		if (!(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED))&&
			(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)))
		{
#if 0
			//TODO: to be enabled at future date
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND REMOTE _NON_ CONNECTED &&& SUSPENDED Session: CLEARING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			ClearLocalSessionCache(NULL, sesn_ptr, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//we dont unlock
#endif
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND REMOTE CONNECTED Session: IGNORING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		}

		//TODO: check backend in bulk operation
		//SessionUnLock (sesn_ptr);

//					continue;
		//code flows naturally to unlock_session below
	}
	else
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: UNABLE TO ASCERTAIN THE STATE OF ORPHAN SESSION: Forcibly suspending...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		SuspendThisSession (NULL, sesn_ptr, 0); suspended_flag=true;
	}

	if (recycle_flag)	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_SESN_HARDSPENDED);

	if (suspended_flag)	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_SESN_SOFTSPENDED);
#endif

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief: Lifecycle callback invoked when IO error is encounteredandbefore Session is (soft) suspended.
 *  Protocol can use this occasion to flush out buffers cleanly. Socket i/o most likely unavailable. This may not
 * 	be an error from the protocols perspective.
 */
UFSRVResult *
proto_sfu_error_callback (Session *sesn_ptr, unsigned call_flags)
{
#if 0
	int rescode=RESCODE_PROG_NULL_POINTER;
	SocketMessage *sock_msg_ptr=SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr);//&sesn_ptr->ssptr->socket_msg;
	onion_connection_status st;

	if (SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)==NULL)
	{
		_LOGD(LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), RESCODE_PROG_INCONSISTENT_STATE, "Empty HttpRequest object");
		rescode=RESCODE_PROG_INCONSISTENT_STATE;

		goto exit_error;
	}

	st=onion_request_write(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr), (const char *)sock_msg_ptr->_processed_msg/*buffer*/, sock_msg_ptr->processed_msg_size/* len*/);
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu') NOTICE: SESNSTATUS_IOERROR IS FALGGED: NOT PROCESSING FURTHER",
				__func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr));
	}

	//have to be careful with this as io flag is on
	#if 1
	if (st!=OCS_NEED_MORE_DATA)
	{
		if (st==OCS_REQUEST_READY)
		{
			st=onion_request_process(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)); // May give error to the connection, or yield or whatever.
			if (st==OCS_CLOSE_CONNECTION)
			{
				//success case singular connection
				rescode=	RESCODE_IO_MSGPARSED;
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): SUCCESS: HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr), st);
			}
			else
			if(st==OCS_KEEP_ALIVE)
			{
				rescode=RESCODE_IO_MSGPARSED;
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'cid:'%lu'): HTTP KEEPALIVE CONNECTION: SHOULD BE KEPT AROUND FOR PEER RESUMPTION", __func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr));
			}
			else
			{
				rescode=RESCODE_PROG_NULL_POINTER;
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: UNKNOWN HANDLER RETURN VALEU: '%d': TERMINATING CONNECTION...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), st);
			}
		}
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED: (frame_coundt='%lu' missing_msg_size: '%lu') RETURNING...",
				__func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr), sock_msg_ptr->frame_count, sock_msg_ptr->missing_msg_size);

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_FRAGMENTATION);

	}
#endif
#endif

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_FRAGMENTATION);


}

UFSRVResult *
proto_sfu_recycler_error_callback (Session *sesn_ptr, unsigned call_flags)
{
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
}

UFSRVResult *
proto_sfu_close_callback (Session *sesn_ptr)
{

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

UFSRVResult *
proto_stun_msgqueue_topics_callback (UFSRVResult *res_ptr)
{

	return NULL;

}

UFSRVResult *
proto_sfu_generate_session_id_callback(UFSRVResult *res_ptr, ClientContextData *context_data)
{
  unsigned long session_id = GenerateSessionIdLocally();
  if (session_id == 0) {
    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_DATA)
  } else {
    _RETURN_RESULT_RES(res_ptr, (uintptr_t)(unsigned long)session_id, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_DATA)
  }
}
