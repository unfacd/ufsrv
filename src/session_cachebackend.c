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
#include <utils.h>
#include <hiredis.h>
#include <redis.h>
#include <session.h>
#include <session_cachebackend.h>

extern __thread ThreadContext ufsrv_thread_context;

/**
 * 	@brief: Set a single value for  fence
 */
UFSRVResult *
CacheBackendSetSessionAttribute (Session *sesn_ptr, unsigned long userid, const char *attribute_name, const char *attribute_value)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_SESSION_SET_ATTRIBUTE, userid, attribute_name, IS_STR_LOADED(attribute_value)?attribute_value:CONFIG_DEFAULT_PREFS_STRING_VALUE)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER && (redis_ptr->integer>=0)) {
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * @brief Retrieves a given session attribute's value
 * @param user_id
 * @param attribute_name as defined in preferences
 * @dynamic_memory: EXPORTS redisReply *
 * @return
 */
UFSRVResult *
CacheBackendGetSessionAttribute (unsigned long user_id, const char *attribute_name)
{
  UFSRVResult *res_ptr  = THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context);

  if (likely(user_id > 0)) {
    redisReply 					*redis_ptr	=	NULL;

    redis_ptr = RedisSendCommand (THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context), REDIS_CMD_SESSION_GET_ATTRIBUTE, user_id, attribute_name);

    if (IS_EMPTY(redis_ptr)) {
      syslog(LOG_DEBUG, "%s pid:'%lu', th_ctx:'%p'}: ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, pthread_self(), &ufsrv_thread_context, user_id);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
    }

    if (redis_ptr->type == REDIS_REPLY_ERROR) {
      syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, pthread_self(), &ufsrv_thread_context, user_id);

      freeReplyObject(redis_ptr);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA)
    }

    if (redis_ptr->type == REDIS_REPLY_NIL) {
      syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: COULD NOT RETRIEVE RECORD FOR UID '%lu'",  __func__, pthread_self(), &ufsrv_thread_context, user_id);

      freeReplyObject(redis_ptr);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
    }

    if (IS_EMPTY(redis_ptr->str)) {
      syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', uid:'%lu', type:'%d'}: ERROR: EMPTY SET FOR UID",  __func__, pthread_self(), &ufsrv_thread_context, user_id,  redis_ptr->type);

      freeReplyObject(redis_ptr);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA)
    }

    _RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
  }

  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}