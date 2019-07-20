/*
 * thread_context_type.h
 *
 *  Created on: 29Nov.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_THREAD_CONTEXT_TYPE_H_
#define SRC_INCLUDE_THREAD_CONTEXT_TYPE_H_

#include <pthread.h>
#include <ufsrvresult_type.h>
#include <adt_hopscotch_hashtable.h>
#include <persistance_type.h>
#include <db_sql.h>
#include <instrumentation_backend.h>
#include <ufsrvmsgqueue_type.h>
#include <http_request_context_type.h>
#include <ratelimit_type.h>

typedef struct ThreadContext {
	HopscotchHashtableConfigurable 			*ht_ptr;
	PersistanceBackend 			*persistance_backend;//loaded from thread-specific data at service time
	InstrumentationBackend 	*instrumentation_backend;//loaded from thread-specific data at service time
	UserMessageCacheBackend *usrmsg_cachebackend;
	FenceCacheBackend				*fence_cachebackend;
	MessageQueueBackend 		*msgqueue_backend;//msg queue publisher loaded from thread-specific data at service time
	DbBackend 							*db_backend;//sql db handle
	UFSRVResult							*res_ptr; //thread specific independent of Session's
	HttpRequestContext 			*http_request_context;
	RequestRateLimitStatus   *ratelimit_status;

	pthread_key_t worker_persistance_key;//each thread gets its own instance of persistance object
	pthread_key_t	worker_usrmsg_cachebackend_key; //redis cachbackend
	pthread_key_t	worker_fence_cachebackend_key; //redis cachbackend
	pthread_key_t ufsrv_http_request_context_key;//
	pthread_key_t ufsrv_instrumentation_backend_key;//instrumentation
	pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue publisher redis connection
	pthread_key_t ufsrv_db_backend_key;//ufsrv db backend access
	pthread_key_t ufsrv_locked_objects_store_key;//key to access currently locked objects held by thread instance
} ThreadContext;

#define THREAD_CONTEXT									(ufsrv_thread_context)
#define THREAD_CONTEXT_PTR							&(ufsrv_thread_context)
#define THREAD_CONTEXT_OBJECT_STORE(x) 	(x.ht_ptr)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE(x)	(THREAD_CONTEXT_UFSRV_RESULT(x)->result_type)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_EQUALS(x, y)	(THREAD_CONTEXT_UFSRV_RESULT(x)->result_type == (y))
#define THREAD_CONTEXT_UFSRV_RESULT_CODE(x)	(THREAD_CONTEXT_UFSRV_RESULT(x)->result_code)
#define THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(x, y)	(THREAD_CONTEXT_UFSRV_RESULT_CODE(x) == y)
#define THREAD_CONTEXT_UFSRV_RESULT(x)	(x.res_ptr)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS(x)	(THREAD_CONTEXT_UFSRV_RESULT_TYPE(x) == RESULT_TYPE_SUCCESS)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR(x)	(THREAD_CONTEXT_UFSRV_RESULT_TYPE(x) == RESULT_TYPE_ERR)
#define THREAD_CONTEXT_DB_BACKEND(x)		(x.db_backend)
#define THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(x)		(x.persistance_backend)
#define THREAD_CONTEXT_FENCE_CACHEBACKEND(x)					(x.fence_backend)
#define THREAD_CONTEXT_USRMSG_CACHEBACKEND(x)					(x.usrmsg_cachebackend)

#endif /* SRC_INCLUDE_THREAD_CONTEXT_TYPE_H_ */
