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
#include <thread_context_type.h>
#include <utils.h>
#include <message.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <include/guardian_record_descriptor.h>

extern __thread ThreadContext ufsrv_thread_context;

inline static UFSRVResult *_GetAllStagedMessageCacheRecordsIndexForUser (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_DeleteStagedMessageCacheRecordsForUser (Session *sesn_ptr, unsigned long userid, time_t now_in_millis_in, redisReply *);
inline static UFSRVResult *_DeleteStagedMessagesLock (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_InstateStagedMessagesLock (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_GetStagedMessageCacheRecordsForUserInJson (Session *sesn_ptr_carrier, unsigned long userid, CollectionDescriptor *collection_ptr, bool);
inline static size_t 			_GetAllStagedMessageCacheRecordsForUser (Session *sesn_ptr, redisReply *redis_ptr_raw_messages, unsigned long userid, redisReply **replies_out);

UFSRVResult *_DbBackendGetMessageStatus (unsigned long eid);

/**
 * 	@brief: For each individual, ready to be sent, user-addressable message we store an index entry and hash entry for the actual message ( protobuf packed message)
 */
UFSRVResult *
StoreStagedMessageCacheRecordForUser (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned long userid)
{
	int	rescode	= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;
	if (unlikely(IS_EMPTY(tmsg_ptr)))			goto return_final;

	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_ADD, userid, GetTimeNowInMillis(), tmsg_ptr->fid, tmsg_ptr->eid);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_ADD, userid, tmsg_ptr->fid, tmsg_ptr->eid,tmsg_ptr->len, tmsg_ptr->msg_packed,tmsg_ptr->len);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t		commands_processed=4,
						commands_successful=4;

	{
		size_t 			i;
		redisReply	*replies[commands_processed];

		//TODO: we need error recover for intermediate errors
		for (i=0; i<commands_processed; i++)
		{
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i])) != REDIS_OK)
			{
				commands_successful--;

				if ((replies[i] != NULL))
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, i, replies[i]->str);
				}
				else
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
				}
			}

			if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
		}
	}

	if (commands_successful!=commands_processed)	{rescode=RESCODE_BACKEND_DATA_PARTIALSET; goto return_final;}

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief: Remove individual cache record from staged storage index and hash
 */
UFSRVResult *
DeleteStagedMessageCacheRecordForUser (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned long userid)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;

	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_DEL, userid, tmsg_ptr->fid, tmsg_ptr->eid);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_REM, userid, tmsg_ptr->fid, tmsg_ptr->eid);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t		commands_processed=4,
						commands_successful=4;

	//TODO: error recovery not done well...
	{
			size_t 			i;
			redisReply	*replies[commands_processed];

			//TODO: we need error recover for intermediate errors
			for (i=0; i<commands_processed; i++)
			{
				if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i])) != REDIS_OK)
				{
					commands_successful--;

					if ((replies[i] != NULL))
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, i, replies[i]->str);
					}
					else
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
					}
				}

				if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
			}
		}

		if (commands_successful!=commands_processed)	{rescode=RESCODE_BACKEND_DATA_PARTIALSET; goto return_final;}

		return_success:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED);

		return_final:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

		return_generic_error:
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
		return _ufsrv_result_generic_error;

}

UFSRVResult *
GetStageMessageCacheBackendListSize (Session *sesn_ptr, unsigned long userid)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_USRMSG_CACHEBACKEND;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, pers_ptr, REDIS_CMD_STAGED_OUTMSG_EVENT_COUNT, userid)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
		size_t list_sz = (size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) list_sz, RESULT_TYPE_SUCCESS, rescode)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
		rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: Main interface for retrieving queued messages for users
 * 	@returns json_object *: raw json containing reply
 * 	@dynamic_memory redisReply *: INSTANTIATES and DEALLOCATES LOCALLY
 * 	@dynamic_memory json_object *: EXPORTS
 */
UFSRVResult *
GetStagedMessageCacheRecordsForUserInJson (Session *sesn_ptr, unsigned long userid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;

	int 		rescode							= RESCODE_PROG_NULL_POINTER;
	time_t	time_now_in_millis	=	GetTimeNowInMillis();

	int counter =  100;
	while(counter) {
		_InstateStagedMessagesLock(sesn_ptr, userid);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_LOCKED)) DoBusyWait(counter--);
		else break;
	}

	if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: COULD NOT OBTAIN LOCK ON RESOURCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),  userid);
#endif
		rescode = RESCODE_BACKEND_RESOURCE_LOCKED;
		goto return_final;
	}

	redisReply 	*redis_ptr;
	json_object *jobj_messages = NULL;

	_GetAllStagedMessageCacheRecordsIndexForUser(sesn_ptr, userid);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		//we get this even if zero result set. We manage memroy here
		redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
		rescode = SESSION_RESULT_CODE(sesn_ptr);//remember it before it gets overwritten

		if (rescode == RESCODE_BACKEND_DATA) {
			redisReply *replies_index[redis_ptr->elements];

			size_t records_returned_sz = _GetAllStagedMessageCacheRecordsForUser(sesn_ptr, redis_ptr, userid, replies_index);

			if (records_returned_sz > 0) {
				_GetStagedMessageCacheRecordsForUserInJson(sesn_ptr, userid, &((CollectionDescriptor){(collection_t **)replies_index, records_returned_sz}), true);

				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))		jobj_messages = (json_object *)SESSION_RESULT_USERDATA(sesn_ptr);//returned to caller

				_DeleteStagedMessageCacheRecordsForUser(sesn_ptr, userid, time_now_in_millis, redis_ptr);
			}
		}

		_DeleteStagedMessagesLock(sesn_ptr, userid);

		//we have to use rescode, because the call above wil overwrite it
		if (rescode == RESCODE_BACKEND_DATA_EMPTYSET)	goto return_error_empty_set;
		//else fall through to return_success
	} else {
		_DeleteStagedMessagesLock(sesn_ptr, userid);
		rescode = SESSION_RESULT_CODE(sesn_ptr);
		goto return_final;
	}

	return_success:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, jobj_messages, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: REDIS RESULTSET for RESPONSE. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),  userid, redis_ptr->str);
	goto return_free;

	return_error_nil_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu'): ERROR: NIL REPLY",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_free;

	return_error_empty_set:
#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu'): NOTICE: RECEIVED EMPTY SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
#endif
	goto return_free;

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief: Helper function, returning json-formatted records of user staged messages
 * 	@param collection_ptr: A collection containing raw redis records
 * 	@dynamic_memory redisReply *: IMPORTS AND DEALLOCATES elements in array of redisReply *
 * 	@dynamic_memory json_object *: EXPORTS json_oject *. Caller responsible for DEALLOCATION
 * 	@returns: where there is no error and the data setset is empty this still returned as SUCESS and caller must retrieve
 * 	and deallocate redisReply *
 */
inline static UFSRVResult *
_GetStagedMessageCacheRecordsForUserInJson (Session *sesn_ptr_carrier, unsigned long userid, CollectionDescriptor *collection_ptr, bool flag_delete_item)
{
	int rescode;

	if (collection_ptr->collection_sz == 0)	{rescode = RESCODE_BACKEND_DATA_EMPTYSET; goto return_error_empty_set;}

	size_t 				i,
								processed_sz = 0;
	//unsigned long sesn_call_flags				=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY);
	//Session 			*sesn_ptr_target			=	GetSessionForThisUserByUserId(sesn_ptr_carrier, userid, sesn_call_flags);
	json_object 	*jobj_envelope,
								*jobj_messages,
								*jobj_messages_array	=	json_object_new_array();

	for (i=0; i < collection_ptr->collection_sz; ++i) {
		size_t 						packed_sz;
		WebSocketMessage 	*websocket_msg_ptr;
		redisReply 				*redis_ptr_indexed;

		redis_ptr_indexed = (redisReply *)collection_ptr->collection[i];
		unsigned char *packed_sz_str = (unsigned char *)strchr((char *)redis_ptr_indexed->str,  ':');
		if (IS_PRESENT(packed_sz_str)) {
			*packed_sz_str = '\0'; //axe the ':'
			unsigned char *packed_msg = ++packed_sz_str;
			packed_sz_str = (unsigned char *)redis_ptr_indexed->str; //repoint to the begining of the original str the '0' will taper it to the size

			if (strlen((char *)packed_sz_str) <= UINT64_LONGEST_STR_SZ) {
				void 		*envelope_payload;
				size_t	envelope_payload_sz;

				packed_sz		= strtol((char *)packed_sz_str, NULL, 10);//size of the WebSocket message stored in redis
				websocket_msg_ptr = web_socket_message__unpack(NULL, packed_sz, packed_msg);
				if(IS_PRESENT(websocket_msg_ptr)) {
					switch (websocket_msg_ptr->type)
					{
						case WEB_SOCKET_MESSAGE__TYPE__REQUEST:
							envelope_payload = websocket_msg_ptr->request->body.data;
							envelope_payload_sz = websocket_msg_ptr->request->body.len;
							break;
						case WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
							envelope_payload = websocket_msg_ptr->response->body.data;
							envelope_payload_sz = websocket_msg_ptr->response->body.len;
							break;

						default:
							web_socket_message__free_unpacked(websocket_msg_ptr, NULL);
							syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: UNRECOGNISED WESOCKETMESSAGE TYPE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);

							if (flag_delete_item) freeReplyObject(redis_ptr_indexed);
							continue;
					}

					unsigned char envelope_b64buf[GetBase64BufferAllocationSize(envelope_payload_sz)];
					if (base64_encode((const unsigned char *)envelope_payload, envelope_payload_sz, envelope_b64buf)) {
						jobj_envelope = json_object_new_object();
						json_object_object_add (jobj_envelope,"message", json_object_new_string((const char *)envelope_b64buf));
						json_object_array_add(jobj_messages_array, jobj_envelope);

						processed_sz++;
					} else {
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: COULD NOT B64 ENCODE ENVELOPE CONTENT", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);
					}

					web_socket_message__free_unpacked(websocket_msg_ptr, NULL);
				}//websocket present
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu', packed_sz:'%lu'): ERROR: ERRENUOUS PACKED MSG SIZE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i, strlen((char *)packed_sz_str));
			}

			if (flag_delete_item)	freeReplyObject(redis_ptr_indexed);
		} else {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: COULD NOT PARSE PACKED MSG SIZE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);
		}
	}

	if (processed_sz > 0) {
		jobj_messages = json_object_new_object();
		json_object_object_add(jobj_messages,"messages", jobj_messages_array);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu', set_sz:'%lu', processed_set_sz:'%lu'): PROCESSED MESSAGES",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, collection_ptr->collection_sz, processed_sz);
#endif

		_RETURN_RESULT_SESN(sesn_ptr_carrier, jobj_messages, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	return_error_empty_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu'): ERROR: RECEIVED EMPTY SET",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: processor for the outcome of _GetAllStagedMessageCacheRecordsIndexForUser()
 * 	dynmic_memroy: EXPORTS redisreply * in provided collection storage replies_out. User responsible for deallocating individual replies
 * 	@returns: raw protobuf messages stored for user
 *
 */
inline static size_t
_GetAllStagedMessageCacheRecordsForUser (Session *sesn_ptr, redisReply *redis_ptr_raw_messages, unsigned long userid, redisReply **replies_out)
{
	if (redis_ptr_raw_messages->elements == 0)	return 0;

	size_t 				i            = 0,
								processed_sz = 0;
	PersistanceBackend	*pers_ptr	= SESSION_USRMSG_CACHEBACKEND(sesn_ptr);

	for (i=0; i < redis_ptr_raw_messages->elements; ++i) {
		(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_GET, userid, (char *)redis_ptr_raw_messages->element[i]->str);
	}

	size_t commands_processed = 0;
	redisReply	**replies = replies_out;

	for (i=0; i<redis_ptr_raw_messages->elements; i++) {
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[commands_processed])) != REDIS_OK) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, userid);

			//TODO: we should probably abort if we ever get a NULL
			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}

			if (!IS_EMPTY(replies[commands_processed]))	freeReplyObject(replies[commands_processed]);
			continue;//we don't want this record in the returned collection
		}

		commands_processed++;
	}

	return commands_processed;

}

/**
 * 	@brief: Returns index of all messages currently stored for user in the cache backend. Another
 * 	operation is need to actually retrieve the message payload for each indexed message in thelist
 *
 * 	@dynamic_memory redisReply *: EXPORTS
 * 	@returns:raw redis collection even ehere restultset is zer except if that was related to error.
 */
inline static UFSRVResult *
_GetAllStagedMessageCacheRecordsIndexForUser (Session *sesn_ptr, unsigned long userid)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;

	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	redis_ptr = (*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_GETALL, userid);

	if (unlikely(IS_EMPTY(redis_ptr))) 	{rescode=RESCODE_BACKEND_CONNECTION; 		goto return_error_backend_connection;}
	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_error_reply;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_error_nil;

	if (redis_ptr->elements == 0) {
		rescode=RESCODE_BACKEND_DATA_EMPTYSET;

#ifdef __UF_FULLDEBUG
			  	 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', uid:'%lu'): NOTICE: EMPTY SET FOR USER STAGED MESSAGES",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
#endif

		goto return_success;
	}

	rescode = RESCODE_BACKEND_DATA;

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, rescode);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', userid:'%lu'): ERROR: REDIS RESULTSET for RESPONSE. Error: '%s'", __func__, pthread_self(), sesn_ptr, userid, redis_ptr->str);
	goto return_free;

	return_error_nil:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', userid:'%lu'): ERROR: NIL RESPONSE RECEIVED. Error: '%s'", __func__, pthread_self(), sesn_ptr, userid, redis_ptr->str);
	goto return_free;

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief: Deletes all current staged messages for user, both the index and the hash records.
 * 	@param: container for redisReply **, containing raw redis records from the STAGED_OUTMSG_EVENTS zindex in teh form of <%fid>:<%eid>. check REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_ADD.
 *
 * 	@dynamic_memory redisReply *: IMPORTS BUT DOES DEALLOCATE
 * 	@dynamic_memroy redisReply *: INSTANTIATES AND DEALLOCATES from cachbackend retrieval
 */
inline static UFSRVResult *
_DeleteStagedMessageCacheRecordsForUser (Session *sesn_ptr, unsigned long userid, time_t now_in_millis_in, redisReply *redis_ptr_indexed_set)
{
	time_t now_in_millis=now_in_millis_in==0?GetTimeNowInMillis():now_in_millis_in;
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			return _ufsrv_result_generic_error;//goto return_generic_error;
	if (IS_EMPTY(redis_ptr_indexed_set) || redis_ptr_indexed_set->elements<=0)
	{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: EMPTY INDEX SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
		//goto return_error_empty_index_set;
	}

	{
	size_t i=0;
	size_t command_buf_sz=0;
	size_t command_buf_szs[redis_ptr_indexed_set->elements];

	for (i=0; i<redis_ptr_indexed_set->elements; i++)
	{
		command_buf_sz+=({command_buf_szs[i]=strlen((char *)redis_ptr_indexed_set->element[i]->str);});
		//command_buf_sz+=strlen((char *)redis_ptr_indexed_set->element[i]->str);
	}

	if (command_buf_sz==0)
	{
		//return
	}

	//hdel buket 1 2
	size_t command_header_sz=strlen(REDIS_CMD_STAGED_OUTMSG_MSG_COMMAND_HEADER)+UINT64_LONGEST_STR_SZ+1; //1 for space after userid
	char *command_buf_walker_ptr;
	char command_buf[command_header_sz+command_buf_sz+redis_ptr_indexed_set->elements+1];//we need to allocate extra single space between hashnames
	memset (command_buf, '\0', sizeof(command_buf));

	command_buf_walker_ptr=command_buf;

	sprintf(command_buf, REDIS_CMD_STAGED_OUTMSG_MSG_COMMAND_HEADER "%lu ", userid);
	command_buf_walker_ptr+=strlen(command_buf);

	for (i=0; i<redis_ptr_indexed_set->elements; i++)
	{
		sprintf(command_buf_walker_ptr, "%s ", (char *)redis_ptr_indexed_set->element[i]->str);
		command_buf_walker_ptr+=command_buf_szs[i]+1;
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu' userid:'%lu', set_sz:'%lu'): Final HDEL COMMAND: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, redis_ptr_indexed_set->elements, command_buf);
#endif

	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_buf);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_EXPIRE, userid, now_in_millis);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t		commands_processed=4,
						commands_successful=4;

	//TODO: error recovery not done well...
	{
			size_t 			i;
			redisReply	*replies[commands_processed];

			//TODO: we need error recover for intermediate errors
			for (i=0; i<commands_processed; i++)
			{
				if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i])) != REDIS_OK)
				{
					commands_successful--;

					if ((replies[i] != NULL))
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, i, replies[i]->str);
					}
					else
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
					}
				}

				if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
			}
		}

		if (commands_successful!=commands_processed)	{rescode=RESCODE_BACKEND_DATA_PARTIALSET; goto return_final;}

		return_success:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED);

		return_error_empty_index_set:
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: EMPTY INDEX SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
		goto return_final;

		return_final:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

		return_generic_error:
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
		return _ufsrv_result_generic_error;
	}

	return _ufsrv_result_generic_error;
#if 0
	if (unlikely(IS_EMPTY(redis_ptr))) 		{rescode=RESCODE_BACKEND_CONNECTION; 		goto return_error_backend_connection;}
	if (unlikely(redis_ptr->type==REDIS_REPLY_ERROR))															goto return_error_reply;
	if (redis_ptr->type==REDIS_REPLY_NIL)	{rescode=RESCODE_BACKEND_DATA_EMPTYSET; goto return_error_nil_set;}

	return_success:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_LOCKED);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu' userid:'%lu'): ERROR COULD ISSUE ZREMRANGEBYSCORE COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_final;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: REDIS RESULTSET for RESPONSE. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, redis_ptr->str);
	goto return_free;

	return_error_nil_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_free;

	return_error_empty_index_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: EMPTY INDEX SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_finale;

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;
#endif
}

inline static UFSRVResult *
_InstateStagedMessagesLock (Session *sesn_ptr, unsigned long userid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	goto return_generic_error;

	int rescode=RESCODE_PROG_NULL_POINTER;
	redisReply *redis_ptr=(*sesn_ptr->usrmsg_cachebackend->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGEDINMSG_PLOCK, userid, "L", 60L);

	if (unlikely(IS_EMPTY(redis_ptr))) 		{rescode=RESCODE_BACKEND_CONNECTION; 		goto return_error_backend_connection;}
	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_error_reply;
	if (redis_ptr->type==REDIS_REPLY_NIL)	{rescode=RESCODE_BACKEND_RESOURCE_LOCKED; goto return_error_nil_set;}

	return_success:
	//should be string value "OK"
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu' userid:'%lu'): ERROR COULD INVKE SCRIPT: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_final;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: REDIS RESULTSET for RESPONSE. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, redis_ptr->str);
	goto return_free;

	return_error_nil_set:
#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: RESOURCE LOCK ALREADY IN PLACE",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
#endif
	goto return_free;

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

inline static UFSRVResult *
_DeleteStagedMessagesLock (Session *sesn_ptr, unsigned long userid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	goto return_generic_error;

	int rescode=RESCODE_PROG_NULL_POINTER;

	redisReply *redis_ptr=(*sesn_ptr->usrmsg_cachebackend->send_command)(sesn_ptr,  SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGEDINMSG_DEL_PLOCK, REDIS_SCRIPT_SHA1_DEL_LOCK, userid);

	if (unlikely(IS_EMPTY(redis_ptr))) 		{rescode=RESCODE_BACKEND_CONNECTION; 		goto return_error_backend_connection;}
	if (redis_ptr->type==REDIS_REPLY_ERROR)																				goto return_error_reply;
	if (redis_ptr->type==REDIS_REPLY_NIL)	{rescode=RESCODE_BACKEND_DATA_EMPTYSET; goto return_error_nil_set;}

	return_success:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu' userid:'%lu'): ERROR COULD INVKE SCRIPT: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_final;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: REDIS RESULTSET for RESPONSE. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, redis_ptr->str);
	goto return_free;

	return_error_nil_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', userid:'%lu'): ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
	goto return_free;

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

///////////// TRANSMITTED / STAGED INTRA MESSAGES \\\\\\\\\\\\\\\\\

/**
 * 	Capture incoming messages directed at users from other users in a staging place until confirmed delivered by the sending service
 * 	@return: the actual named payload as stored in redis. This canbe used to perform named retrieval of this specific record.
 * 	@dynamic_memory char *: EXPORTS IF NOT provided by user
 */
UFSRVResult *
StoreStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  unsigned long call_flags, unsigned char *command_buf_in)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;
	if (unlikely(IS_EMPTY(msg_desc_ptr)))	goto return_final;

	size_t							command_buf_sz			=	msg_desc_ptr->rawmsg_sz+MBUF;
	unsigned char 			*command_buf;
	PersistanceBackend	*pers_ptr						= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	if (IS_EMPTY(command_buf_in))	command_buf = calloc(command_buf_sz, sizeof(unsigned char));
	else													command_buf = command_buf_in;

	redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_INTRAMESSAGE_RECORD_ADD,
																			msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup,
																			msg_desc_ptr->instance_descriptor_ptr->reqid,
																			msg_desc_ptr->instance_descriptor_ptr->reqid, msg_desc_ptr->msg_type, msg_desc_ptr->rawmsg, msg_desc_ptr->rawmsg_sz);

	if (unlikely(IS_EMPTY(redis_ptr))) {rescode = RESCODE_BACKEND_CONNECTION; goto return_error_backend_connection;}
	if (redis_ptr->integer == 1)	goto return_success;

	goto return_command_error;

	return_success:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, command_buf, RESULT_TYPE_SUCCESS, rescode);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_command_error:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', redis_error:'%s'): ERROR COMMAND RETURNED ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), IS_PRESENT(redis_ptr->str)?redis_ptr->str:"unspecified error");
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief: A main filtering point for interfacing transmitted INTRA messages stored in staging
 */
UFSRVResult *
HandleStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name, enum StoredMessageOptions msg_opts)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))				goto return_error;

	if (msg_opts == MSGOPT_GET_REM_FIRST)
			return GetRemStagedMessageCacheRecordForIntraCommand(sesn_ptr, msg_desc_ptr,  payload_name, msg_opts);
	if (msg_opts == MSGOPT_GET_FIRST || msg_opts == MSGOPT_GET_LAST || msg_opts == MSGOPT_GETALL || msg_opts == MSGOPT_GETNAMED)
			return GetStagedMessageCacheRecordForIntraCommand (sesn_ptr, msg_desc_ptr, payload_name, msg_opts);
	if (msg_opts == MSGOPT_REMOVE) ;//TODO IMPLEMENT

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief:retrieve a record and delete its presence in the backend as one transaction
 * 	@para payloadname: for retrieving a specific record (not implemented)
 * 	@return redisReply *[2]. The actual retrieved payload is at idx=0, which is another redisReplay *
 * 	@dynamic_memory redisreply *: EXPORTS
 */
UFSRVResult *
GetRemStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr_carrier, ParsedMessageDescriptor *msg_desc_ptr,  const char *payload_name, enum StoredMessageOptions msg_opts)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr_carrier)))			goto return_generic_error;
	//if (unlikely(IS_EMPTY(storage_id)))		goto return_final;

	const char 					*command_template_get,
											*command_template_rem;
	PersistanceBackend	*pers_ptr	= sesn_ptr_carrier->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	if (msg_opts == MSGOPT_GET_REM_FIRST) {
		command_template_get = REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST;
		command_template_rem = REDIS_CMD_INTRAMESSAGE_LIST_REM_EARLIEST;
	}
	else if (msg_opts == MSGOPT_GET_REM_LAST) {
		command_template_get = REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST;
		command_template_rem = REDIS_CMD_INTRAMESSAGE_LIST_REM_EARLIEST;
	}
	else if (msg_opts == MSGOPT_GET_REM_ALL) goto return_generic_error;//TODO IMPLEMENT

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), command_template_get, msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), command_template_rem, msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), "EXEC");

	#define COMMAND_SET_SIZE	4
	#define EXEC_COOMAND_IDX (COMMAND_SET_SIZE-1)

	size_t					commands_successful	= COMMAND_SET_SIZE;
	redisReply			*replies[COMMAND_SET_SIZE]; memset (replies, 0, sizeof(replies));

	for (size_t i=0; i<COMMAND_SET_SIZE; i++) {
		if ((RedisGetReply(sesn_ptr_carrier, pers_ptr, (void *)&replies[i])) != REDIS_OK) {
			--commands_successful;

			if ((replies[i] != NULL)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, i, replies[i]->str);
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, i);
			}
		}
	}//for

	if (unlikely(commands_successful != COMMAND_SET_SIZE)) {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NOT ALL COMMAND SUCCESSED: REVOING TRANSACTION", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid);

		for (size_t i=0; i<COMMAND_SET_SIZE; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

	//remove replies upto  EXEC
	for (size_t i=0; i<COMMAND_SET_SIZE-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

	if (unlikely(IS_EMPTY(replies[EXEC_COOMAND_IDX]))) {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE FOR EXEC ELEMENT", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

#define GET_COMMAND_IDX	0
#define REM_COMMAND_IDX 1

	if (likely(replies[EXEC_COOMAND_IDX]->elements == COMMAND_SET_SIZE-2)) {
		if (replies[EXEC_COOMAND_IDX]->element[GET_COMMAND_IDX]->elements == 1) {//this contains the payload in redis array
			if (replies[EXEC_COOMAND_IDX]->element[REM_COMMAND_IDX]->integer == 1) {
				return_success:
				_RETURN_RESULT_SESN(sesn_ptr_carrier, replies[EXEC_COOMAND_IDX], RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
			}
		}

		goto return_error_exec_command;
	}

	return_error_exec_command:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', rem_redis_int:'%llu'): ERROR: EXEC command error", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, replies[EXEC_COOMAND_IDX]->element[REM_COMMAND_IDX]->integer);
	freeReplyObject(replies[EXEC_COOMAND_IDX]);
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL)

	return_generic_error:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL)


#undef COMMAND_SET_SIZE
#undef EXEC_COOMAND_IDX
#undef GET_COMMAND_IDX
#undef REM_COMMAND_IDX
}

/**
 * 	@brief: Get one or set-of records from the staging store for transmitted INTRA messages. retrieval can be positional, or named.
 *
 * 	@param payload_name: used for named record, as opposed to positional (last, first etc)
 * 	@dynamic_meory redisReply *: EXPORTS
 */
UFSRVResult *
GetStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr, const char *payload_name, enum StoredMessageOptions msg_opts)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))			goto return_generic_error;

	const char 					*command_template;
	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	if (msg_opts==MSGOPT_GET_FIRST)						command_template=REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST;
	else if (msg_opts==MSGOPT_GET_LAST)				command_template=REDIS_CMD_INTRAMESSAGE_LIST_GET_LAST;
	else if (msg_opts==MSGOPT_GETALL)					command_template=REDIS_CMD_INTRAMESSAGE_LIST_GETALL;
	else if (msg_opts==MSGOPT_GETNAMED)
	{
		if (unlikely(!IS_STR_LOADED(payload_name)))		goto return_final;
		command_template=REDIS_CMD_INTRAMESSAGE_LIST_GET_NAMED;
	}
	else goto return_final;

	if (msg_opts == MSGOPT_GETNAMED) {
		size_t	command_buf_sz=strlen(payload_name)+strlen(command_template)+10;
		char 		command_buf[command_buf_sz];

		snprintf(command_buf, command_buf_sz, command_template,
						 msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
		redis_ptr = (*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_buf);
	} else {
		redis_ptr = (*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_template,
				msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
	}

	if (unlikely(IS_EMPTY(redis_ptr))) {rescode=RESCODE_BACKEND_CONNECTION; goto return_error_backend_connection;}
	if (redis_ptr->elements>1 && IS_STR_LOADED(redis_ptr->element[0]->str))	goto return_success;

	//must have encountered error in reply
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', redis_error:'%s'): ERROR COULD ISSUE GET COMMAND", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), IS_PRESENT(redis_ptr->str)?redis_ptr->str:"unspecified error");
	freeReplyObject(redis_ptr);
	goto return_final;

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	TODO: This is not finalised yet
 */
UFSRVResult *
RemoveStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name, unsigned long call_flags)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr)))							goto return_generic_error;
	if (unlikely(!IS_STR_LOADED(payload_name)))		goto return_final;

	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	{
		size_t	command_buf_sz=strlen(payload_name)+MBUF;
		char 		command_buf[command_buf_sz+1];

		snprintf(command_buf, command_buf_sz, REDIS_CMD_INTRAMESSAGE_RECORD_REM,
						 	 	 	 	 	 	 	 	 	 	 	 	 	 	 msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup,
																				 payload_name);
		redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_buf);
	}

	if (unlikely(IS_EMPTY(redis_ptr))) {rescode=RESCODE_BACKEND_CONNECTION; goto return_error_backend_connection;}

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

int
DbBackendInsertMessageRecord (const ParsedMessageDescriptor *msg_descriptor_ptr)
{
#define SQL_INSERT_NEW_INCOMING_MESSAGE "INSERT INTO messages (id_events, fid, type, rawmsg, timestamp, originator, originator_device) VALUES ('%lu', '%lu', '%u', '%s', '%lu', '%lu', '%d')"

  char *sql_query_str;
  sql_query_str = mdsprintf(SQL_INSERT_NEW_INCOMING_MESSAGE, msg_descriptor_ptr->gid, msg_descriptor_ptr->fid, msg_descriptor_ptr->msg_type, msg_descriptor_ptr->rawmsg, msg_descriptor_ptr->timestamp, msg_descriptor_ptr->userid_from, DEFAULT_DEVICE_ID);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif
  int sql_result = h_query_insert(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_INSERT_NEW_FENCE
}

/**
 * @brief Flag event status (flagged vs non flagged)
 * @param eid
 * @param status
 * @return
 */
int
DbBackendUpdateMessageStatus (unsigned long gid, unsigned  long uid_flagged_by, enum EventStatus status)
{
#define SQL_UPDATE_MESSAGE_STATUS 	 "UPDATE messages SET status = '%d' WHERE id_events = '%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_MESSAGE_STATUS, status, gid);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {th_ctx:'%p'}: GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', event_rowid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, gid, sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_UPDATE_MESSAGE_STATUS
}

UFSRVResult *
_DbBackendGetMessageStatus (unsigned long eid)
{
#define SQL_GET_MESSAGE_STATUS "SELECT status FROM messages WHERE eid = '%lu'"
#define COLUMN_STATUS(x)	    ((struct _h_type_int *)result.data[0][0].t_data)->value

  struct _h_result result;

  char *sql_query_str = mdsprintf(SQL_GET_MESSAGE_STATUS, eid);

#if __UF_TESTING
  syslog(LOG_DEBUG, "%s {th_ctx:'%p', eid:'%lu'}: GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, eid, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', eid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, eid, sql_query_str);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
  }

  free (sql_query_str);

  //we should ever only find 1 or zero really
  if (result.nb_rows > 0) {
    unsigned status = COLUMN_STATUS(result);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)status, RESCODE_BACKEND_DATA)
  } else {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', eid:'%lu'}: ERROR: COULD RETRIEVE MESSAGE", __func__, THREAD_CONTEXT_PTR, eid);
#endif
  }

  exit_user_not_found:
  h_clean_result(&result);

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)

#undef COLUMN_STATUS
#undef SQL_GET_MESSAGE_STATUS

}

#include <utils_nonce.h>
/**
 *
 * @param sesn_ptr
 * @param value uid idenitifying the guarded
 * @return
 */
char *
GenerateGuardianNonce (Session *sesn_ptr, const char *value)
{
  char *attachment_nonce = BackEndGenerateNonce(sesn_ptr, CONFIGDEFAULT_GUARDIAN_NONCE_EXPIRY, CONFIGDEFAULT_GUARDIAN_NONCE_PREFIX, value);

  return attachment_nonce;

}

unsigned long
IsGuardianLinkNonceValid (const char *nonce, unsigned long supplied_value)
{
  PersistanceBackend *pers_ptr;
  redisReply *redis_ptr;

  if (!IS_STR_LOADED(nonce)) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: NONCE VALUE NOT SET", __func__, pthread_self());
    return 0;
  }

  pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);

  char tmp[LBUF] = {0};
  snprintf(tmp, LBUF-1, "GET %s:%s", CONFIGDEFAULT_GUARDIAN_NONCE_PREFIX, nonce);

  if (!(redis_ptr = (*pers_ptr->send_command)(NULL, tmp))) {
    syslog(LOG_DEBUG, "%s (pid:'%lu' nonce:'%s'): ERROR COULD NOT GET NONCE: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), nonce);

    return false;
  }

  __success_block:
  if (redis_ptr->type == REDIS_REPLY_STRING) {
    unsigned long retrieved_value = strtoul(redis_ptr->str, NULL, 10);

    freeReplyObject(redis_ptr);
    return retrieved_value == supplied_value;
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR COULD NOT GET NONCE: REPLY ERROR '%s'", __func__, pthread_self(), redis_ptr->str);

    freeReplyObject(redis_ptr);

    return 0;
  }

  if (redis_ptr->type == REDIS_REPLY_NIL) {
    syslog(LOG_DEBUG, "%s(pid:'%lu'): ERROR COULD NOT GET STORED NONCE: REPLY NIL '%s'", __func__, pthread_self(), redis_ptr->str);

    freeReplyObject(redis_ptr);

    return 0;
  }

  return 0;

}

/**
 *  {event_types: '[{type:'%u', fid:'%lu'},{}]'}
 * @param descriptor_ptr
 * @return
 */
UFSRVResult *
DbBackendInsertGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr, bool force_data)
{
#define SQL_INSERT_NEW_GUARDIAN_RECORD "INSERT INTO guardians (guardian, originator, status, gid, timestamp, data) VALUES ('%lu', '%lu', '%u', '%lu', '%llu', '%s') ON DUPLICATE KEY UPDATE timestamp = '%llu', gid = '%lu'"
#define SQL_INSERT_NEW_GUARDIAN_RECORD_NO_DATA "INSERT INTO guardians (guardian, originator, status, gid, timestamp) VALUES ('%lu', '%lu', '%u', '%lu', '%llu') ON DUPLICATE KEY UPDATE timestamp = '%llu', gid = '%lu'"
  char *sql_query_str;
  if (force_data) {
    sql_query_str = mdsprintf(SQL_INSERT_NEW_GUARDIAN_RECORD, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid, descriptor_ptr->status, descriptor_ptr->gid, descriptor_ptr->timestamp, descriptor_ptr->specs.specs_serialised, descriptor_ptr->timestamp, descriptor_ptr->gid);
  } else {
    if (!IS_STR_LOADED(descriptor_ptr->specs.specs_serialised)) {
      sql_query_str = mdsprintf(SQL_INSERT_NEW_GUARDIAN_RECORD_NO_DATA, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid, descriptor_ptr->status, descriptor_ptr->gid, descriptor_ptr->timestamp, descriptor_ptr->timestamp, descriptor_ptr->gid);
    } else {
      sql_query_str = mdsprintf(SQL_INSERT_NEW_GUARDIAN_RECORD, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid, descriptor_ptr->status, descriptor_ptr->gid, descriptor_ptr->timestamp, descriptor_ptr->specs.specs_serialised, descriptor_ptr->timestamp, descriptor_ptr->gid);
    }
  }

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif
  int sql_result = h_query_insert(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
  }

  free (sql_query_str);

  struct _h_data *db_data = h_query_last_insert_id(THREAD_CONTEXT_DB_BACKEND);
  if (db_data->type == HOEL_COL_TYPE_INT) {
    int last_id = ((struct _h_type_int *)db_data->t_data)->value;
    h_clean_data_full(db_data);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)last_id, RESCODE_BACKEND_DATA)
  }

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)

#undef SQL_INSERT_NEW_GUARDIAN_RECORD
}

/**
 * @brief Retrieve the guardian record for a named originator/guardian pair.
 * @param descriptor_ptr
 * @return
 */
UFSRVResult *
DbBackendGetGuardianRecord (GuardianRecordDescriptor *descriptor_ptr)
{
#define SQL_GET_GUARDIAN_RECORD "SELECT * FROM guardians WHERE  guardian = '%lu' AND originator = '%lu'"
#define SQL_GET_GUARDIAN_RECORD_WITH_STATUS "SELECT * FROM guardians WHERE  guardian = '%lu' AND originator = '%lu' AND status = '%u'"
#define COLUMN_ID(x)	    ((struct _h_type_int *)result.data[x][0].t_data)->value //0
#define COLUMN_GUARDIAN(x)	    ((struct _h_type_int *)result.data[x][1].t_data)->value
#define COLUMN_ORIGINATOR(x)	    ((struct _h_type_int *)result.data[x][2].t_data)->value
#define COLUMN_STATUS(x)	    ((struct _h_type_int *)result.data[x][3].t_data)->value
#define COLUMN_TIMESTAMP(x)	    ((struct _h_type_int *)result.data[x][4].t_data)->value
#define COLUMN_GID(x)	    ((struct _h_type_int *)result.data[x][5].t_data)->value
#define COLUMN_DATA_IS_EMPTY(x)          IS_EMPTY(((struct _h_type_blob *)result.data[x][6].t_data))
#define COLUMN_DATA(x)          (char *)(((struct _h_type_blob *)result.data[x][6].t_data)->value)
#define COLUMN_DATA_LEN(x)          ((struct _h_type_blob *)result.data[x][6].t_data)->length

  int 	rescode;
  struct _h_result result;
  char *sql_query_str;

  if (descriptor_ptr->status != GUARDIAN_STATUS_NONE) sql_query_str = mdsprintf(SQL_GET_GUARDIAN_RECORD_WITH_STATUS, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid, descriptor_ptr->status);
  else sql_query_str = mdsprintf(SQL_GET_GUARDIAN_RECORD, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK)		goto return_db_error;
  if (result.nb_rows == 0)	goto return_empty_set;
  if (COLUMN_DATA_IS_EMPTY(0))	goto return_db_empty_jsonstr;

  const char *account_data_json_str = strndupa(COLUMN_DATA(0), COLUMN_DATA_LEN(0));
  size_t 			jsonstr_sz = strlen(account_data_json_str);

  if (unlikely(jsonstr_sz == 0))	goto return_db_empty_jsonstr;

  enum 		json_tokener_error jerr;
  json_object 	*jobj_account = NULL;
  json_tokener 	*jtok = json_tokener_new();

  do {
    jobj_account = json_tokener_parse_ex(jtok, account_data_json_str, strlen(account_data_json_str));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success)	goto return_error_json_tokniser;

  //originator and guardian values already set in the provided descriptor_ptr
  unsigned long id = COLUMN_ID(0);
  descriptor_ptr->status = COLUMN_STATUS(0);
  descriptor_ptr->timestamp = COLUMN_TIMESTAMP(0);
  descriptor_ptr->gid = COLUMN_GID(0);
  descriptor_ptr->specs.specs_jobj = jobj_account;

  return_success:
  json_tokener_free(jtok);
  h_clean_result(&result);
  free (sql_query_str);
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)id, RESCODE_BACKEND_DATA)

  return_db_error:
  syslog(LOG_DEBUG, "%s {th_ctx: '%p'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);
  rescode = RESCODE_BACKEND_CONNECTION;
  goto return_free;

  return_empty_set:
#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), THREAD_CONTEXT_PTR);
#endif
  rescode = RESCODE_BACKEND_DATA_EMPTYSET;
  goto return_free_sql_handle;

  return_error_json_tokniser:
  syslog(LOG_NOTICE, "%s (pid:'%lu' th_ctx:'%p'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), THREAD_CONTEXT_PTR, json_tokener_error_desc(jerr));
  rescode = RESCODE_PROG_JSON_PARSER;
  goto return_free_json_tokeniser;

  return_db_empty_jsonstr:
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: DB JSON COLUMN NULL OR STRING SIZE ZERO", __func__, pthread_self(), THREAD_CONTEXT_PTR);
  rescode = RESCODE_BACKEND_RESOURCE_NULL;
  goto return_free_sql_handle;

  return_free_json_tokeniser:
  json_tokener_free(jtok);
  if (IS_PRESENT(jobj_account)) json_object_put(jobj_account);

  return_free_sql_handle:
  h_clean_result(&result);

  return_free:
  free (sql_query_str);

  return_error:
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)

#undef SQL_GET_GUARDIAN_RECORD
#undef COLUMN_ID
#undef COLUMN_GUARDIAN
#undef COLUMN_ORIGINATOR
#undef COLUMN_STATUS
#undef COLUMN_TIMESTAMP
#undef COLUMN_GID
#undef COLUMN_DATA_IS_EMPTY
#undef COLUMN_DATA
#undef COLUMN_DATA_LEN
#undef SQL_GET_GUARDIAN_RECORD
#undef SQL_GET_GUARDIAN_RECORD_WITH_STATUS
}

/**
 * @brief Retrieve all records for the named guardian.
 * @param descriptor_ptr_guardian
 * @param collection_ptr_out Must be allocated by caller. When returned, size will be set > 0
 * @dynamic_memory: EXPORTS GuardianRecordDescriptor **
 * @return
 */
UFSRVResult *
DbBackendGetGuardianRecords (GuardianRecordDescriptor *descriptor_ptr_guardian, CollectionDescriptor *collection_ptr_out)
{
#define SQL_GET_GUARDIAN_RECORD "SELECT * FROM guardians WHERE  guardian = '%lu'"
#define SQL_GET_GUARDIAN_RECORD_WITH_STATUS "SELECT * FROM guardians WHERE  guardian = '%lu' AND status = '%u'"
#define COLUMN_ID(x)	    ((struct _h_type_int *)result.data[x][0].t_data)->value //0
#define COLUMN_GUARDIAN(x)	    ((struct _h_type_int *)result.data[x][1].t_data)->value
#define COLUMN_ORIGINATOR(x)	    ((struct _h_type_int *)result.data[x][2].t_data)->value
#define COLUMN_STATUS(x)	    ((struct _h_type_int *)result.data[x][3].t_data)->value
#define COLUMN_TIMESTAMP(x)	    ((struct _h_type_int *)result.data[x][4].t_data)->value
#define COLUMN_GID(x)	    ((struct _h_type_int *)result.data[x][5].t_data)->value
#define COLUMN_DATA_IS_EMPTY(x)          IS_EMPTY(((struct _h_type_blob *)result.data[x][6].t_data))
#define COLUMN_DATA(x)          (char *)(((struct _h_type_blob *)result.data[x][6].t_data)->value)
#define COLUMN_DATA_LEN(x)          ((struct _h_type_blob *)result.data[x][6].t_data)->length

  int 	rescode;
  struct _h_result result;
  char *sql_query_str;

  if (descriptor_ptr_guardian->status != GUARDIAN_STATUS_NONE) sql_query_str = mdsprintf(SQL_GET_GUARDIAN_RECORD_WITH_STATUS, descriptor_ptr_guardian->guardian.uid, descriptor_ptr_guardian->status);
  else sql_query_str = mdsprintf(SQL_GET_GUARDIAN_RECORD, descriptor_ptr_guardian->guardian.uid);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK)		goto return_db_error;
  if (result.nb_rows == 0)	goto return_empty_set;
  GuardianRecordDescriptor **guardian_records = calloc(result.nb_rows, sizeof(GuardianRecordDescriptor));

#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(guardian_records, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(guardian_records, result.nb_rows * (sizeof(GuardianRecordDescriptor)));
#endif

  GuardianRecordDescriptor *descriptor_ptr;
  size_t i = 0;
  for (; i<result.nb_rows; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(guardian_records, (guardian_records + (i * sizeof(GuardianRecordDescriptor))), sizeof(GuardianRecordDescriptor));
#endif
    descriptor_ptr = (GuardianRecordDescriptor *)(guardian_records + (i * sizeof(GuardianRecordDescriptor)));
    descriptor_ptr->status = COLUMN_STATUS(i);
    descriptor_ptr->timestamp = COLUMN_TIMESTAMP(i);
    descriptor_ptr->gid = COLUMN_GID(i);
    descriptor_ptr->originator.uid = COLUMN_ORIGINATOR(i);
    descriptor_ptr->guardian.uid = COLUMN_GUARDIAN(i);
  }

  return_success:
  collection_ptr_out->collection_sz = result.nb_rows;
  collection_ptr_out->collection = (collection_t **) guardian_records;
  h_clean_result(&result);
  free (sql_query_str);
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)collection_ptr_out, RESCODE_BACKEND_DATA)

  return_db_error:
  syslog(LOG_DEBUG, "%s {th_ctx: '%p'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);
  rescode = RESCODE_BACKEND_CONNECTION;
  goto return_free;

  return_empty_set:
#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), THREAD_CONTEXT_PTR);
#endif
  rescode = RESCODE_BACKEND_DATA_EMPTYSET;
  goto return_free_sql_handle;
  return_free_sql_handle:
  h_clean_result(&result);

  return_free:
  free (sql_query_str);

  return_error:
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)

#undef SQL_GET_GUARDIAN_RECORD
#undef COLUMN_ID
#undef COLUMN_GUARDIAN
#undef COLUMN_ORIGINATOR
#undef COLUMN_STATUS
#undef COLUMN_TIMESTAMP
#undef COLUMN_GID
#undef COLUMN_DATA_IS_EMPTY
#undef COLUMN_DATA
#undef COLUMN_DATA_LEN
#undef SQL_GET_GUARDIAN_RECORD
#undef SQL_GET_GUARDIAN_RECORD_WITH_STATUS
}

UFSRVResult *
DbBackendGetGuardianRecordForOriginator (GuardianRecordDescriptor *descriptor_ptr)
{
#define SQL_GET_ORIGINATOR_RECORD "SELECT * FROM guardians WHERE  originator = '%lu'"
#define SQL_GET_ORIGINATOR_RECORD_WITH_STATUS "SELECT * FROM guardians WHERE  originator = '%lu' AND status = '%u'"
#define COLUMN_ID(x)	    ((struct _h_type_int *)result.data[x][0].t_data)->value //0
#define COLUMN_GUARDIAN(x)	    ((struct _h_type_int *)result.data[x][1].t_data)->value
#define COLUMN_ORIGINATOR(x)	    ((struct _h_type_int *)result.data[x][2].t_data)->value
#define COLUMN_STATUS(x)	    ((struct _h_type_int *)result.data[x][3].t_data)->value
#define COLUMN_TIMESTAMP(x)	    ((struct _h_type_int *)result.data[x][4].t_data)->value
#define COLUMN_GID(x)	    ((struct _h_type_int *)result.data[x][5].t_data)->value
#define COLUMN_DATA_IS_EMPTY(x)          IS_EMPTY(((struct _h_type_blob *)result.data[x][6].t_data))
#define COLUMN_DATA(x)          (char *)(((struct _h_type_blob *)result.data[x][6].t_data)->value)
#define COLUMN_DATA_LEN(x)          ((struct _h_type_blob *)result.data[x][6].t_data)->length

  int 	rescode;
  struct _h_result result;
  char *sql_query_str;

  if (descriptor_ptr->status != GUARDIAN_STATUS_NONE) sql_query_str = mdsprintf(SQL_GET_ORIGINATOR_RECORD_WITH_STATUS, descriptor_ptr->originator.uid, descriptor_ptr->status);
  else sql_query_str = mdsprintf(SQL_GET_ORIGINATOR_RECORD, descriptor_ptr->originator.uid);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK)		goto return_db_error;
  if (result.nb_rows == 0)	goto return_empty_set;
  if (COLUMN_DATA_IS_EMPTY(0))	goto return_db_empty_jsonstr;

  const char *account_data_json_str = strndupa(COLUMN_DATA(0), COLUMN_DATA_LEN(0));
  size_t 			jsonstr_sz = strlen(account_data_json_str);

  if (unlikely(jsonstr_sz == 0))	goto return_db_empty_jsonstr;

  enum 		json_tokener_error jerr;
  json_object 	*jobj_account = NULL;
  json_tokener 	*jtok = json_tokener_new();

  do {
    jobj_account = json_tokener_parse_ex(jtok, account_data_json_str, strlen(account_data_json_str));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success)	goto return_error_json_tokniser;

  unsigned long id = COLUMN_ID(0);
  //originator value already set in the provided descriptor_ptr
  descriptor_ptr->guardian.uid = COLUMN_GUARDIAN(0);
  descriptor_ptr->status = COLUMN_STATUS(0);
  descriptor_ptr->timestamp = COLUMN_TIMESTAMP(0);
  descriptor_ptr->gid = COLUMN_GID(0);
  descriptor_ptr->specs.specs_jobj = jobj_account;

  return_success:
  json_tokener_free(jtok);
  h_clean_result(&result);
  free (sql_query_str);
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)id, RESCODE_BACKEND_DATA)

  return_db_error:
  syslog(LOG_DEBUG, "%s {th_ctx: '%p'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);
  rescode = RESCODE_BACKEND_CONNECTION;
  goto return_free;

  return_empty_set:
#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), THREAD_CONTEXT_PTR);
#endif
  rescode = RESCODE_BACKEND_DATA_EMPTYSET;
  goto return_free_sql_handle;

  return_error_json_tokniser:
  syslog(LOG_NOTICE, "%s (pid:'%lu' th_ctx:'%p'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), THREAD_CONTEXT_PTR, json_tokener_error_desc(jerr));
  rescode = RESCODE_PROG_JSON_PARSER;
  goto return_free_json_tokeniser;

  return_db_empty_jsonstr:
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: DB JSON COLUMN NULL OR STRING SIZE ZERO", __func__, pthread_self(), THREAD_CONTEXT_PTR);
  rescode = RESCODE_BACKEND_RESOURCE_NULL;
  goto return_free_sql_handle;

  return_free_json_tokeniser:
  json_tokener_free(jtok);
  if (IS_PRESENT(jobj_account)) json_object_put(jobj_account);

  return_free_sql_handle:
  h_clean_result(&result);

  return_free:
  free (sql_query_str);

  return_error:
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)

#undef COLUMN_ID
#undef COLUMN_GUARDIAN
#undef COLUMN_ORIGINATOR
#undef COLUMN_STATUS
#undef COLUMN_TIMESTAMP
#undef COLUMN_GID
#undef COLUMN_DATA_IS_EMPTY
#undef COLUMN_DATA
#undef COLUMN_DATA_LEN
#undef SQL_GET_ORIGINATOR_RECORD
#undef SQL_GET_ORIGINATOR_RECORD_WITH_STATUS
}

UFSRVResult *
DbBackendDeleteGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr)
{
#define SQL_DELETE_GUARDIAN_RECORD "DELETE FROM guardians WHERE guardian = '%lu' AND originator = '%lu' AND status = '%u'"

  char *sql_query_str = mdsprintf(SQL_DELETE_GUARDIAN_RECORD, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid, descriptor_ptr->status);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: GENERATED SQL QUERY: '%s'", __func__,  pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_delete(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), NULL, 0UL, sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  free (sql_query_str);

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

#undef SQL_DELETE_GUARDIAN_RECORD
}

UFSRVResult *
CacheBackendAddGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr)
{
  PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
  unsigned 						rescode			=	RESCODE_BACKEND_DATA;
  redisReply 					*redis_ptr	=	NULL;

  if (!(redis_ptr = (*pers_ptr->send_command)(NULL, REDIS_CMD_GUARDIAN_ADD, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid)))	goto return_redis_error;

  if (redis_ptr->type == REDIS_REPLY_INTEGER) {
    return_success:
    freeReplyObject(redis_ptr);
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
  if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

  return_redis_error:
  if (IS_EMPTY(redis_ptr)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), THREAD_CONTEXT_PTR);
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: REDIS RESULT-SET. Error: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, redis_ptr->str);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }
  if (redis_ptr->type == REDIS_REPLY_NIL) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: NIL SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }

  return_error:
  freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
}

UFSRVResult *
CacheBackendRemGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr)
{
  unsigned 						rescode			=	RESCODE_BACKEND_DATA;
  PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
  redisReply 					*redis_ptr	=	NULL;

  if (!(redis_ptr = (*pers_ptr->send_command)(NULL, REDIS_CMD_GUARDIAN_REM, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid)))	goto return_redis_error;

  if (redis_ptr->type == REDIS_REPLY_INTEGER) {
    return_success:
    freeReplyObject(redis_ptr);
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
  if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

  return_redis_error:
  if (IS_EMPTY(redis_ptr)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), THREAD_CONTEXT_PTR);
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, redis_ptr->str);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }
  if (redis_ptr->type == REDIS_REPLY_NIL) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: NIL SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }

  return_error:
  freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
}

UFSRVResult *
CacheBackendGetGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr)
{
  PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
  unsigned 						rescode			=	RESCODE_BACKEND_DATA;
  redisReply 					*redis_ptr	=	NULL;

  if (!(redis_ptr = (*pers_ptr->send_command)(NULL, REDIS_CMD_FENCE_GUARDIAN_ISMEMBER, descriptor_ptr->guardian.uid, descriptor_ptr->originator.uid)))	goto return_redis_error;

  if (redis_ptr->type == REDIS_REPLY_INTEGER) {
    long long int is_member=redis_ptr->integer;
    return_success:
    freeReplyObject(redis_ptr);
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)is_member, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
  if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

  return_redis_error:
  if (IS_EMPTY(redis_ptr)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), THREAD_CONTEXT_PTR);
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: REDIS RESULT-SET. Error: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, redis_ptr->str);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }
  if (redis_ptr->type == REDIS_REPLY_NIL) {
    syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p'}: ERROR: NIL SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR);
    rescode = RESCODE_BACKEND_DATA; goto return_error;
  }

  return_error:
  freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
}

bool
IsUserGuardianFor (const GuardianRecordDescriptor *descriptor_ptr)
{
  CacheBackendGetGuardianRecord(descriptor_ptr);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    bool is_member = (bool)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
    return is_member;
  }

  return false;
}

#if 0
//NOT SURE THIS IS NEEDED we already implement GET ABOVE
/**
 * 	@brief: global store of incoming user messages
 */
UFSRVResult *
GetMessageFromCacheRecords (Session *sesn_ptr, unsigned long call_flags)

{
	int rescode										= RESCODE_PROG_NULL_POINTER;
	Fence 							*f_ptr		=	NULL;
	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_INMESSAGES_LIST_GETALL, SESSION_USERID(sesn_ptr));

	if (unlikely(IS_EMPTY(redis_ptr))) {rescode=RESCODE_BACKEND_CONNECTION; goto return_error_backend_connection;}
	if (redis_ptr->elements==0)
	{
		if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_error_backend_error;
		if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_error_backend_nil;

		rescode=RESCODE_BACKEND_DATA_EMPTYSET; goto return_empty_set;
	}

	{
	   //we now have a list of UID's
#ifdef __UF_TESTING
//	syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', fid:'%lu'}: RESULT: Fence contains (%lu) users in it", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), redis_ptr->elements);
#endif
		size_t		i, success_counter=0;
		redisReply	*sesn_ptr_list[redis_ptr->elements];
		UFSRVResult	res;

		//retrieve the raw user cache record for each uid and index it into list
		for (i=0; i < redis_ptr->elements; ++i)
		{
			 unsigned long 	user_id		= strtol(redis_ptr->element[i]->str, NULL, 10);
			 UFSRVResult 		*res_ptr	= SessionGetFromBackendRaw (sesn_ptr, sesn_ptr, user_id, 0, &res);

			 if (_RESULT_TYPE_SUCCESS(res_ptr))
			 {
				 redisReply *redis_ptr_user=((redisReply *)res_ptr->result_user_data);
				 *(sesn_ptr_list+success_counter++)=redis_ptr_user;
			 }
			 else
			 {
				 //TODO: this a stale UID which must cleanse. perhaps log it in a list for out of band processing?
				 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', uid:'%lu'): ERROR: FOUND POTENTIALLY STALE UID --> TODO: IMPELMENT CLEANSING",
							 __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), user_id);
			 }
		}

		//we now have a list of user record each entry represented by raw redisReply *
		if (success_counter)
		{
		}

		if (success_counter < redis_ptr->elements)
		{
		 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: Received '%lu' elements: BUT ONLY PROCESED '%lu' WITH SUCCESS...",
				 __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->elements, success_counter);
		}

		good_finish:
		for (i=0; i < success_counter; ++i)	 freeReplyObject(sesn_ptr_list[i]);
		freeReplyObject(redis_ptr);
		SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_EPHEMERAL);

		_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

	}
	/////////
	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_error_backend_error:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD NOT GET: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	goto on_return_free;

	return_error_backend_nil:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD NOT GET: NIL REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	goto on_return_free;

	return_empty_set:
#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p): NOTICE: EMPTY SET",  __func__, pthread_self(), sesn_ptr);
#endif
	goto on_return_free;

	on_return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;


}
#endif

#if 0
UFSRVResult *
AddMessageCacheRecordForUsers (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr, UfsrvMsgCommandType msg_type, const unsigned char *b64encoded_rawmsg, unsigned long call_flags)
{
	size_t 							i,
											actually_processed=0;
	int rescode										= RESCODE_PROG_NULL_POINTER;
	PersistanceBackend	*pers_ptr	= sesn_ptr->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	for (i=0; i<msg_desc_ptr->userids_to.collection_sz; i++)
	{
		(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_INMESSAGE_RECORD_ADD, *((unsigned long **)msg_desc_ptr->userids_to.collection)[i], time(NULL),
				msg_type, msg_desc_ptr->fid, msg_desc_ptr->userid_from, b64encoded_rawmsg);

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', idx:'%lu'}: Processing Collection item for user...", __func__, pthread_self(), sesn_ptr, *((unsigned long **)msg_desc_ptr->userids_to.collection)[i], i);
#endif
	}
	(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");


	actually_processed=msg_desc_ptr->userids_to.collection_sz+2;
	redisReply	*replies[actually_processed];
	for (i=0; i<actually_processed; i++)	replies[i]=NULL;

	//TODO: we need error recover for intermediate errors
	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i]) != REDIS_OK))
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd_idx:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, i);

			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL))
			{
				//error msg
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}
		}
	}

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	goto return_final;

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}
#endif


#if 0
//NOT IMPELEMENTED
UFSRVResult *
DbBackendInsertUserMessageByProto (Session *sesn_ptr, MessageCommand *msg_cmd_ptr, unsigned char *msg_cmd_raw)
{

	unsigned long verification_code;

	{


#define SQL_INSERT_USER_MESSAGE "INSERT INTO messages (fid, source, source_device, timestamp, message, recipients) VALUES ('%s', '%s')"

		const char	*username;
		const char	*nickname_unvalidated;
		char		*nickname_validated=NULL;;
		char *msg_cmd_b64encoded=base64_encode(msg_cmd_raw, int length);
		//this will hold top level fields
		struct json_object *jobj_account=json_object_new_object();
		{
			username=json_object_get_string(json__get(jobj_device, "number"));

			nickname_unvalidated=json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_NICKNAME));
			if (nickname_unvalidated!=NULL)
			{
				AccountNicknameValidateForUniqueness(sesn_ptr, NULL, nickname_unvalidated, false);//can't store because account doesnt exist yet
				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
				{
					nickname_validated=strdup(nickname_unvalidated);

					//store it at account level
					json_object_object_add (jobj_account, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(nickname_validated));
				}
				else
				{
					//no need to check if current nickname  equals roposed because there is no current
					json_object_object_add (jobj_account, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
				}

				//remove it from device level; it was there as a carried reference only
				json_object_object_del (jobj_device, ACCOUNT_JSONATTR_NICKNAME);
			}
			else
			{
				nickname_unassigned:
				json_object_object_add (jobj_account, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', username:'%s'}: No Nickname was present: assigning default", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr));
#endif
			}

			json_object_object_add (jobj_account, "number", json_object_new_string(username));
			//TODO: supplied in another stream. but is currently saved at device level, so this maybe bogus entry
			json_object_object_add (jobj_account, "identity_key", json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
			json_object_object_add (jobj_account, "authenticated_device", jobj_device);

			//attach master device to array of devices
			struct json_object *jarray_accounts=json_object_new_array();
			json_object_array_add (jarray_accounts, jobj_device);

			//attach the arry to the main account node
			json_object_object_add (jobj_account, "devices", jarray_accounts);
		}

		const char *json_account_str=json_object_to_json_string(jobj_account);
		syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED JSON ACCOUNT: '%s'", __func__, SESSION_ID(sesn_ptr), json_account_str);

		char *sql_query_str;
		sql_query_str=mdsprintf(SQL_INSERT_NEW_ACCOUNT, username, json_account_str);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif
		int sql_result=h_query_insert(sesn_ptr->db_backend, sql_query_str);

		//this seems to be necessary, because the same object is attached twice. The reference in the array remains (valgrind complaint)
		json_object_object_del(jobj_account, "authenticated_device");
		json_object_put(jobj_account);

		if (sql_result!=H_OK)
		{
			syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
		}

		free (sql_query_str);

		//cache. Should be done more broadly
		if (nickname_validated)
		{
			BackendDirectoryNicknameSet (sesn_ptr, nickname_validated);
			SESSION_USERNICKNAME(sesn_ptr)=nickname_validated;//strdup reference gets deleted at user session destruction time
		}

		return sql_result;
	}

	return H_ERROR;

#undef SQL_INSERT_NEW_ACCOUNT
}
#endif

