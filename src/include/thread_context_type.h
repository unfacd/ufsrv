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
#include <uflib/adt/adt_hopscotch_hashtable.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <uflib/db/db_sql.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue_type.h>
#include <http_request_context_type.h>
#include <ufsrv_core/ratelimit/ratelimit_type.h>

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
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_	(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT)->result_type)
#define THREAD_CONTEXT_UFSRV_RESULT_USERDATA  (THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT)->result_user_data)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_EQUALS(x, y)	(THREAD_CONTEXT_UFSRV_RESULT(x)->result_type == (y))
#define THREAD_CONTEXT_UFSRV_RESULT_CODE(x)	(THREAD_CONTEXT_UFSRV_RESULT(x)->result_code)
#define THREAD_CONTEXT_UFSRV_RESULT_CODE_	(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT)->result_code)
#define THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(x, y)	(THREAD_CONTEXT_UFSRV_RESULT_CODE(x) == y)
#define THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL_(x)	(THREAD_CONTEXT_UFSRV_RESULT_CODE_ == x)
#define THREAD_CONTEXT_UFSRV_RESULT(x)	(x.res_ptr)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS	(THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_SUCCESS)
#define THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA (THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_SUCCESS && THREAD_CONTEXT_UFSRV_RESULT_CODE(THREAD_CONTEXT) == RESCODE_BACKEND_DATA)
#define THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA (THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_SUCCESS && THREAD_CONTEXT_UFSRV_RESULT_CODE(THREAD_CONTEXT) == RESCODE_BACKEND_DATA_EMPTYSET)
#define THREAD_CONTEXT_UFSRV_RESULT_IS_EMPTYSET_BACKEND_DATA ((THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_ERR || THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_SUCCESS) && THREAD_CONTEXT_UFSRV_RESULT_CODE(THREAD_CONTEXT) == RESCODE_BACKEND_DATA_EMPTYSET)
#define THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR	(THREAD_CONTEXT_UFSRV_RESULT_TYPE(THREAD_CONTEXT) == RESULT_TYPE_ERR)
#define THREAD_CONTEXT_DB_BACKEND		(THREAD_CONTEXT.db_backend)
#define THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(x)		(x.persistance_backend)
#define THREAD_CONTEXT_FENCE_CACHEBACKEND					(THREAD_CONTEXT.fence_cachebackend)
#define THREAD_CONTEXT_USRMSG_CACHEBACKEND					(THREAD_CONTEXT.usrmsg_cachebackend)
#define THREAD_CONTEXT_MSGQUEUE_CACHEBACKEND					(THREAD_CONTEXT.msgqueue_backend)
#define THREAD_CONTEXT_INSTRUMENTATION_BACKEND					(THREAD_CONTEXT.instrumentation_backend)
#define THREAD_CONTEXT_HTTP_REQUEST_CONTEXT					(THREAD_CONTEXT.http_request_context)

#define THREAD_CONTEXT_RETURN_RESULT_SUCCESS(x, y)    \
{\
	THREAD_CONTEXT.res_ptr->result_user_data=(void *)x;\
	THREAD_CONTEXT.res_ptr->result_type=RESULT_TYPE_SUCCESS;\
	THREAD_CONTEXT.res_ptr->result_code=y;\
	return THREAD_CONTEXT.res_ptr;\
}

#define THREAD_CONTEXT_RETURN_RESULT_ERROR(x, y)    \
{\
	THREAD_CONTEXT.res_ptr->result_user_data=(void *)x;\
	THREAD_CONTEXT.res_ptr->result_type=RESULT_TYPE_ERR;\
	THREAD_CONTEXT.res_ptr->result_code=y;\
	return THREAD_CONTEXT.res_ptr;\
}

#endif /* SRC_INCLUDE_THREAD_CONTEXT_TYPE_H_ */
