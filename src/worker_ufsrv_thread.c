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

#include <sys/prctl.h>//for naming thread
#include <thread_context_type.h>
#include <sockets.h>
#include <utils.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket_io.h>
#include <http_request.h>
#include <json/json.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <uflib/db/db_sql.h>
#include <sessions_delegator_type.h>
#include <uflib/adt/adt_hopscotch_hashtable.h>
#include <uflib/scheduled_jobs/scheduled_jobs.h>

static MessageContextData *_WorkerThreadScheduledJobExtractArg(MessageQueueMsgPayload *msgqueue_payload_ptr);

//lookup table for matching delegator type to associated callback function
static WorkerJobSpecs worker_job_specs[]={
		{DELEGTYPE_TIMER,	 		NULL, WorkerThreadScheduledJobExecutor, 						_WorkerThreadScheduledJobExtractArg				},
		{DELEGTYPE_MSGQUEUE, 	NULL, WorkerThreadMsgQueueParserExecutor, 					WorkerThreadMessageQueueParserExtractArg	}
};

 extern __thread/*thread_local*/ ThreadContext      ufsrv_thread_context;

__attribute__((const)) static MessageContextData *
_WorkerThreadScheduledJobExtractArg(MessageQueueMsgPayload *msgqueue_payload_ptr)
{
  return ((MessageContextData *)msgqueue_payload_ptr->payload);
}

void *
ThreadUFServerWorker (void *ptr)
{
	HopscotchHashtableConfigurable locked_objects_store = {0};
	HttpRequestContext 	http_request_context = {0};
	SessionsDelegator 	*sd_ptr = NULL;
	UFSRVResult					ufsrv_result = {0};

	sd_ptr = (SessionsDelegator *)ptr;

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufServerWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	pthread_setspecific(sd_ptr->ufsrv_thread_pool.ufsrv_thread_context_key, (void *)&ufsrv_thread_context);

	hopscotch_init(&(locked_objects_store.hashtable), CONFIG_THREAD_LOCKED_OBJECTS_STORE_PFACTOR);
	locked_objects_store.keylen = 0;
	locked_objects_store.keylen = 64;
	locked_objects_store.hash_func = (uint64_t (*)(uint8_t *, size_t))inthash_u64;

	ufsrv_thread_context.ht_ptr = &locked_objects_store;

	ufsrv_thread_context.res_ptr = &ufsrv_result;

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		if (IS_PRESENT(InitialiseHttpRequestContext(&http_request_context, 0))) {
			pthread_setspecific(sd_ptr->ufsrv_thread_pool.ufsrv_http_request_context_key, (void *)&http_request_context);//TODO: move key to delegator structure
			ufsrv_thread_context.http_request_context = &http_request_context;
		} else {
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
			_exit(-1);
		}

		syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Ufsrv Worker thread: '%lu'...", __func__, &http_request_context, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  InstrumentationBackend *instr_ptr = InstrumentationBackendInit (NULL);//no namespace
	if (instr_ptr) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key, (void *)instr_ptr);
		ufsrv_thread_context.instrumentation_backend = instr_ptr;
	} else {
		syslog(LOG_NOTICE, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
	}

	syslog(LOG_INFO, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Ufsrv Worker thread: '%lu' (NOT IMPLEMENTED)...", __func__, instr_ptr, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  struct _h_connection *db_ptr = InitialiseDbBackend();
	if (db_ptr) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure
		ufsrv_thread_context.db_backend = db_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  PersistanceBackend *per_ptr = InitialisePersistanceBackend(NULL);
	if (per_ptr) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.worker_persistance_key, (void *)per_ptr);
		ufsrv_thread_context.persistance_backend = per_ptr;
	} else {
		syslog(LOG_ERR, "ThreadUFServerWorker: ERROR: COULD NOT INITIALISE Session Cache Backend for Ufsrv Worker thread: '%lu'...", pthread_self());
		exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised Session Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  UserMessageCacheBackend *per_ptr_usrmsg = InitialiseCacheBackendUserMessage(NULL);
	if (per_ptr_usrmsg) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.worker_usrmsg_cachebackend_key, (void *)per_ptr_usrmsg);
		ufsrv_thread_context.usrmsg_cachebackend = per_ptr_usrmsg;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s : SUCCESS: Initialised UserMessage Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

			//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  FenceCacheBackend *per_ptr_fence = InitialiseCacheBackendFence(NULL);
	if (per_ptr_fence) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.worker_fence_cachebackend_key, (void *)per_ptr_fence);
		ufsrv_thread_context.fence_cachebackend = per_ptr_fence;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s : SUCCESS: Initialised Fence Cache Backend for Ufsrv Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

  MessageQueueBackend *mq_ptr = InitialiseMessageQueueBackend(NULL);
	if (mq_ptr) {
		pthread_setspecific(sd_ptr->ufsrv_thread_pool.ufsrv_msgqueue_pub_key, (void *)mq_ptr);
		ufsrv_thread_context.msgqueue_backend = mq_ptr;
	} else {
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for UfServerWorker thread: '%lu'...", __func__, pthread_self());
		exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised MessageQueue Publisher Backend for UfServerWorker thread: '%lu'...", __func__, pthread_self());
  syslog(LOG_INFO, "%s: --> Launching into main loop: pid:'%lu', ufsrv_th_ctx:'%p'", __func__, pthread_self(), &ufsrv_thread_context);

	while (1) {
#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu): --------- ", pthread_self());
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu'): BEGIN COND_WAIT EVENT: Acquiring work queue mutex lock and fetching job... I may block", pthread_self());
#endif

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		pthread_mutex_lock(&(sd_ptr->ufsrv_thread_pool.work_queue_mutex));
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:'%lu'): Successfully acquired mutex lock... (1)", pthread_self());
#endif

		while ((sd_ptr->ufsrv_thread_pool.ufsrv_work_queue.nEntries == 0) && (sd_ptr->up_status == 1)) {
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): Mutex automatically released(-1): Blocking on condition: waiting for signal: queue_not_empty_cond", __func__, pthread_self());
#endif
			pthread_cond_wait(&(sd_ptr->ufsrv_thread_pool.queue_not_empty_cond), &(sd_ptr->ufsrv_thread_pool.work_queue_mutex));
		}

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "ThreadUFServerWorker (pid:%lu): WORK SIGNAL: mutex lock automatically acquired (1) ", pthread_self());
#endif

		//lock now acquired automatically by pthreads.. we unlock at the end

#if 0
		//NOT IN USE
		if (sd_ptr->up_status==0)
		{
			syslog(LOG_INFO, "ThreadUFServerWorker (pid:%lu): UFServer Worker Manager is shutting down: releasing mutext lock (-1) exiting...", pthread_self());
			pthread_mutex_unlock(&(sd_ptr->ufsrv_thread_pool.work_queue_mutex));
			pthread_exit(NULL);
		}
#endif
		syslog(LOG_DEBUG, "%s (pid:%lu): RETRIEVING JOB: Queue size (cnt='%lu')...", __func__, pthread_self(), sd_ptr->ufsrv_thread_pool.ufsrv_work_queue.nEntries);

		//work_queue_mutex lock state: locked
		QueueEntry *qe_ptr = NULL;
		qe_ptr = deQueue(&(sd_ptr->ufsrv_thread_pool.ufsrv_work_queue));

		if (sd_ptr->ufsrv_thread_pool.ufsrv_work_queue.nEntries == 0)	pthread_cond_signal(&(sd_ptr->ufsrv_thread_pool.queue_empty_cond));//<<<<<<<

		//syslog(LOG_DEBUG, "ThreadWebSockets (pid:%lu): END COND_WAIT EVENT: Releasing mutex lock (-1):  performing ufsrv work...", pthread_self());

		//reengage the pool main loop
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		pthread_mutex_unlock(&(sd_ptr->ufsrv_thread_pool.work_queue_mutex));
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		//do work
		{
			//syslog(LOG_DEBUG, "ThreadWebSockets (pid:%lu): BEGIN:  performing ufsrv work...", pthread_self());

			if (IS_PRESENT(qe_ptr)  && IS_PRESENT(qe_ptr->whatever)) {
				MessageQueueMsgPayload 		*mqp_ptr						=	(MessageQueueMsgPayload *)qe_ptr->whatever;
				CallbackWorkArgExtractor 	extract_work_arg		=	worker_job_specs[mqp_ptr->delegator_type].fetch_work_arg;

				(*worker_job_specs[mqp_ptr->delegator_type].work_exec)(extract_work_arg(mqp_ptr));

				free (qe_ptr->whatever);
				free (qe_ptr);
			} else {
				syslog(LOG_ERR, "%s (pid:%lu): ERROR: QUEUE Entry was NULL...", __func__, pthread_self());
			}
		}
	}

}



