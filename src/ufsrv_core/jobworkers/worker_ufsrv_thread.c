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
 * This is a worker thread responsible for executing jobs assigned through the job queue using broadcast semantics.
 */
#ifdef HAVE_CONFIG_H
# include "include/config.h"
#endif

#include <sys/prctl.h>//for naming thread
#include "thread_context_type.h"
#include "jobworkers/worker_ufsrv_thread.h"
#include "jobworkers/base_thread_context_data_type.h"
#include "sockets.h"
#include "nportredird.h"
#include "http_request.h"
#include <json/json.h>
#include "ufsrv_core/instrumentation/instrumentation_backend.h"
#include "msgqueue_backend/ufsrvcmd_broadcast.h"
#include "include/sessions_delegator_type.h"
#include "uflib/adt/adt_hopscotch_hashtable.h"
#include "uflib/scheduled_jobs/scheduled_jobs.h"
#include "ufsrv_core/include/jobworkers/worker_job_descriptor_type.h"
#include "user_callback_job.h"

static MessageContextData *_WorkerThreadScheduledJobExtractArg(MessageQueueMsgPayload *msgqueue_payload_ptr);
static MessageContextData *_WorkerThreadGenericArgsExtractor(MessageQueueMsgPayload *msgqueue_payload_ptr);

//see scheduled_jobs.c as an example of how to make this dynamic and registerable at start time
//lookup table for matching delegator type to associated callback function
static WorkerJobDescriptor worker_job_specs[] = {
    {DELEGTYPE_UNINITIALISED,         NULL, NULL, 	                                          NULL				                              },
    {DELEGTYPE_USER_CALLBACK,         NULL, WorkerThreadUserCallbackJobExecutor,              _WorkerThreadGenericArgsExtractor         },
		{DELEGTYPE_TIMER,	 		            NULL, WorkerThreadScheduledJobExecutor,                 _WorkerThreadScheduledJobExtractArg				},
		{DELEGTYPE_MSGQUEUE, 	            NULL, WorkerThreadMsgQueueParserExecutor,                WorkerThreadMessageQueueParserExtractArg	},
    {DELEGTYPE_TIMER_FIRST_INSERTED,  NULL, WorkerThreadScheduledJobFirstInsertedExecutor,    _WorkerThreadScheduledJobExtractArg				},
    {DELEGTYPE_INVALID, 	            NULL, NULL, 	                                          NULL	                                    },
};

//todo this replaces old pthread thread-specific storage keys. Storage declared in delegator_session_io_worker_thread.c
extern __thread ThreadContext      ufsrv_thread_context; //declared in delegator
//extern __thread ThreadContext      *ufsrvworker_thread_context;//to replace above
//static __thread BaseThreadContext *base_thread_context;
extern __thread BaseThreadContext *base_thread_context; //allocation defined in sfu delegator

__attribute__((const)) static MessageContextData *
_WorkerThreadScheduledJobExtractArg(MessageQueueMsgPayload *msgqueue_payload_ptr)
{
  return ((MessageContextData *)msgqueue_payload_ptr->payload);
}

static __attribute__((const)) MessageContextData *
_WorkerThreadGenericArgsExtractor(MessageQueueMsgPayload *msgqueue_payload_ptr)
{
  return (MessageContextData *)(msgqueue_payload_ptr->payload);
}

static void *_ThreadUFServerWorker(void *ptr);

BaseThreadContext *
GetBaseThreadContextForUfsrvWorker(void)
{
  return base_thread_context;
}

ufsrvworker_thread_callback
GetUfsrvWorkerThreadHandler(void)
{
  return  &_ThreadUFServerWorker;
}

/**
 * Generic job worker thread
 * @param ptr
 * @return
 */
static void *
_ThreadUFServerWorker(void *ptr)
{
	HopscotchHashtableConfigurable locked_objects_store = {0};
	HttpRequestContext 	http_request_context = {0};
	UFSRVResult					ufsrv_result = {0};

  base_thread_context = ptr;
  if (IS_PRESENT(base_thread_context->user_thread_context)) {
    ufsrv_thread_context = *(ThreadContext *)base_thread_context->user_thread_context;//struct-copy: to be replaced by statement below
  }

  ufsrv_thread_context.random_state = time(NULL) ^ getpid() ^ pthread_self(); //set to a seed value before rand_r is called for the first time

  WorkerPoolDescriptor *workers_pool = base_thread_context->pool_descriptor;

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy(proc_name, "ufServerWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl(PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	if (!IS_EMPTY(workers_pool->thread_handlers.on_instantiated)) {
    workers_pool->thread_handlers.on_instantiated(base_thread_context);
	}

//	//todo: this is the old pthread_key based implementation. Delete one the thread_local implementation is finalised.
//	pthread_setspecific(sd_ptr->jobworkers.ufsrv_thread_context_key, (void *)&ufsrv_thread_context);
//
//	hopscotch_init(&(locked_objects_store.hashtable), CONFIG_THREAD_LOCKED_OBJECTS_STORE_PFACTOR);
//	locked_objects_store.keylen = 0;
//	locked_objects_store.keylen = 64;
//	locked_objects_store.hash_func = (uint64_t (*)(uint8_t *, size_t))inthash_u64;
//
//	ufsrv_thread_context.ht_ptr = &locked_objects_store;
//
//	ufsrv_thread_context.res_ptr = &ufsrv_result;
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//		if (IS_PRESENT(InitialiseHttpRequestContext(&http_request_context, 0))) {
//			pthread_setspecific(sd_ptr->jobworkers.ufsrv_http_request_context_key, (void *)&http_request_context);//TODO: move key to delegator structure
//			ufsrv_thread_context.http_request_context = &http_request_context;
//		} else {
//			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//			_exit(-1);
//		}
//
//		syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, &http_request_context, pthread_self());
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//  InstrumentationBackend *instr_ptr = InstrumentationBackendInit (NULL);//no namespace
//	if (instr_ptr) {
//		pthread_setspecific(sd_ptr->jobworkers.ufsrv_instrumentation_backend_key, (void *)instr_ptr);
//		ufsrv_thread_context.instrumentation_backend = instr_ptr;
//	} else {
//		syslog(LOG_NOTICE, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//	}
//
//	syslog(LOG_INFO, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Ufsrv Worker thread: '%lu' (NOT IMPLEMENTED)...", __func__, instr_ptr, pthread_self());
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//  struct _h_connection *db_ptr = InitialiseDbBackend();
//	if (db_ptr) {
//		pthread_setspecific(sd_ptr->jobworkers.ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure
//		ufsrv_thread_context.db_backend = db_ptr;
//	} else {
//		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//		_exit (-1);
//	}
//
//	syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//  PersistanceBackend *per_ptr = InitialisePersistanceBackend(NULL);
//	if (per_ptr) {
//		pthread_setspecific(sd_ptr->jobworkers.worker_persistance_key, (void *)per_ptr);
//		ufsrv_thread_context.persistance_backend = per_ptr;
//	} else {
//		syslog(LOG_ERR, "ThreadUFServerWorker: ERROR: COULD NOT INITIALISE Session Cache Backend for Ufsrv Worker thread: '%lu'...", pthread_self());
//		exit (-1);
//	}
//
//	syslog(LOG_INFO, "%s: SUCCESS: Initialised Session Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//  UserMessageCacheBackend *per_ptr_usrmsg = InitialiseCacheBackendUserMessage(NULL);
//	if (per_ptr_usrmsg) {
//		pthread_setspecific(sd_ptr->jobworkers.worker_usrmsg_cachebackend_key, (void *)per_ptr_usrmsg);
//		ufsrv_thread_context.usrmsg_cachebackend = per_ptr_usrmsg;
//	} else {
//		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//		_exit (-1);
//	}
//
//	syslog(LOG_INFO, "%s : SUCCESS: Initialised UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//
//			//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//  FenceCacheBackend *per_ptr_fence = InitialiseCacheBackendFence(NULL);
//	if (per_ptr_fence) {
//		pthread_setspecific(sd_ptr->jobworkers.worker_fence_cachebackend_key, (void *)per_ptr_fence);
//		ufsrv_thread_context.fence_cachebackend = per_ptr_fence;
//	} else {
//		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//		_exit (-1);
//	}
//
//	syslog(LOG_INFO, "%s : SUCCESS: Initialised Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//
//  MessageQueueBackend *mq_ptr = BuildConnectionHandleForMessageQueueBackend(NULL);
//	if (mq_ptr) {
//		pthread_setspecific(sd_ptr->jobworkers.ufsrv_msgqueue_pub_key, (void *)mq_ptr);
//		ufsrv_thread_context.msgqueue_backend = mq_ptr;
//	} else {
//		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for UfServerWorker thread: '%lu'...", __func__, pthread_self());
//		exit (-1);
//	}
//
//	syslog(LOG_INFO, "%s: SUCCESS: Initialised MessageQueue Publisher Backend for UfServerWorker thread: '%lu'...", __func__, pthread_self());

  syslog(LOG_INFO, "%s: --> Launching into main loop: pid:'%lu', ufsrv_th_ctx:'%p'", __func__, pthread_self(), base_thread_context);

	while (1) {
#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu): --------- ", pthread_self());
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu'): BEGIN COND_WAIT EVENT: Acquiring work queue mutex lock and fetching job... I may block", pthread_self());
#endif

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		pthread_mutex_lock(&(workers_pool->workers_pool_config_descriptor.work_queue_mutex));
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu'): Successfully acquired mutex lock... (1)", pthread_self());
#endif

		while ((workers_pool->workers_pool_config_descriptor.ufsrv_work_queue.nEntries == 0) && (workers_pool->workers_pool_config_descriptor.up_status == POOL_STATE_UP)) {
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): Mutex automatically released(-1): Blocking on condition: waiting for signal: queue_not_empty_cond", __func__, pthread_self());
#endif
			pthread_cond_wait(&(workers_pool->workers_pool_config_descriptor.queue_not_empty_cond), &(workers_pool->workers_pool_config_descriptor.work_queue_mutex));
		}

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:%lu): WORK SIGNAL: mutex lock automatically acquired (1) ", pthread_self());
#endif

		//lock now acquired automatically by pthreads.. we unlock at the end

#if 0
		//NOT IN USE
		if (workers_pool->workers_pool_config_descriptor.up_status == POOL_STATE_SUSPENDED || workers_pool->workers_pool_config_descriptor.up_status == POOL_STATE_DOWN)
		{
			syslog(LOG_INFO, "ThreadUFServerWorker (pid:%lu): UFServer Worker Manager is shutting down: releasing mutext lock (-1) exiting...", pthread_self());
			pthread_mutex_unlock(&(workers_pool->workers_pool_config_descriptor.work_queue_mutex));
			pthread_exit(NULL);
		}
#endif
		syslog(LOG_DEBUG, "%s (pid:%lu): RETRIEVING JOB: Queue size (cnt='%lu')...", __func__, pthread_self(), workers_pool->workers_pool_config_descriptor.ufsrv_work_queue.nEntries);

		//work_queue_mutex lock state: locked
		QueueEntry *qe_ptr = NULL;
		qe_ptr = deQueue(&(workers_pool->workers_pool_config_descriptor.ufsrv_work_queue));

		if (workers_pool->workers_pool_config_descriptor.ufsrv_work_queue.nEntries == 0)	pthread_cond_signal(&(workers_pool->workers_pool_config_descriptor.queue_empty_cond));//<<<<<<<

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu): END COND_WAIT EVENT: Releasing mutex lock (-1):  performing ufsrv work...", __func__, pthread_self());
#endif

		//reengage the pool main loop
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		pthread_mutex_unlock(&(workers_pool->workers_pool_config_descriptor.work_queue_mutex));
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		//do work
		{
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:%lu): BEGIN:  performing ufsrv work...", __func__, pthread_self());
#endif
			if (IS_PRESENT(qe_ptr)  && IS_PRESENT(qe_ptr->whatever)) {
				MessageQueueMsgPayload 		*mqp_ptr						=	(MessageQueueMsgPayload *)qe_ptr->whatever;
				CallbackWorkArgExtractor 	extract_work_arg		=	worker_job_specs[mqp_ptr->delegator_type].fetch_work_arg;

				(*worker_job_specs[mqp_ptr->delegator_type].work_exec)(extract_work_arg(mqp_ptr));

				free(qe_ptr->whatever);
				free(qe_ptr);
			} else {
				syslog(LOG_ERR, "%s (pid:%lu): ERROR: QUEUE Entry was NULL...", __func__, pthread_self());
			}
		}
	}

	return NULL;
}



