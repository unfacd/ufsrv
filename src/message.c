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
#include <redis.h>

extern __thread ThreadContext ufsrv_thread_context;

inline static UFSRVResult *_GetAllStagedMessageCacheRecordsIndexForUser (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_DeleteStagedMessageCacheRecordsForUser (Session *sesn_ptr, unsigned long userid, time_t now_in_millis_in, redisReply *);
inline static UFSRVResult *_DeleteStagedMessagesLock (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_InstateStagedMessagesLock (Session *sesn_ptr, unsigned long userid);
inline static UFSRVResult *_GetStagedMessageCacheRecordsForUserInJson (Session *sesn_ptr_carrier, unsigned long userid, CollectionDescriptor *collection_ptr, bool);
inline static size_t 			_GetAllStagedMessageCacheRecordsForUser (Session *sesn_ptr, redisReply *redis_ptr_raw_messages, unsigned long userid, redisReply **replies_out);

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
	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_USRMSG_CACHEBACKEND(ufsrv_thread_context);
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, pers_ptr, REDIS_CMD_STAGED_OUTMSG_EVENT_COUNT, userid)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER) {
		size_t list_sz=(size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) list_sz, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
		rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

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

	int counter=100;
	while(counter)
	{
		_InstateStagedMessagesLock(sesn_ptr, userid);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_LOCKED)) DoBusyWait(counter--);
		else break;
	}

	if (SESSION_RESULT_TYPE_ERROR(sesn_ptr))
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: COULD NOT OBTAIN LOCK ON RESOURCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),  userid);
#endif
		rescode=RESCODE_BACKEND_RESOURCE_LOCKED;
		goto return_final;
	}

	redisReply 	*redis_ptr;
	json_object *jobj_messages=NULL;

	_GetAllStagedMessageCacheRecordsIndexForUser (sesn_ptr, userid);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
	{
		//we get this even if zero result set. We manage memroy here
		redis_ptr=(redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
		rescode=SESSION_RESULT_CODE(sesn_ptr);//remember it before it gets overwritten

		if (rescode==RESCODE_BACKEND_DATA)
		{
			redisReply *replies_index[redis_ptr->elements];

			size_t records_returned_sz=_GetAllStagedMessageCacheRecordsForUser (sesn_ptr, redis_ptr, userid, replies_index);

			if (records_returned_sz>0)
			{
				_GetStagedMessageCacheRecordsForUserInJson (sesn_ptr, userid, &((CollectionDescriptor){(collection_t **)replies_index, records_returned_sz}), true);

				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))		jobj_messages=(json_object *)SESSION_RESULT_USERDATA(sesn_ptr);//returned to caller

				_DeleteStagedMessageCacheRecordsForUser (sesn_ptr, userid, time_now_in_millis, redis_ptr);
			}
		}

		_DeleteStagedMessagesLock (sesn_ptr, userid);

		//we have to use rescode, because the call above wil overwrite it
		if (rescode==RESCODE_BACKEND_DATA_EMPTYSET)	goto return_error_empty_set;
		//else fall through to return_success
	}
	else
	{
		_DeleteStagedMessagesLock (sesn_ptr, userid);
		rescode=SESSION_RESULT_CODE(sesn_ptr);
		goto return_final;
	}


	return_success:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, jobj_messages, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

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
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

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

	if (collection_ptr->collection_sz==0)	{rescode=RESCODE_BACKEND_DATA_EMPTYSET; goto return_error_empty_set;}

	size_t 				i,
								processed_sz=0;
	//unsigned long sesn_call_flags				=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY);
	//Session 			*sesn_ptr_target			=	GetSessionForThisUserByUserId(sesn_ptr_carrier, userid, sesn_call_flags);
	json_object 	*jobj_envelope,
								*jobj_messages,
								*jobj_messages_array	=	json_object_new_array();

	for (i=0; i < collection_ptr->collection_sz; ++i)
	{
		size_t 						packed_sz;
		WebSocketMessage 	*websocket_msg_ptr;
		redisReply 				*redis_ptr_indexed;

		redis_ptr_indexed=(redisReply *)collection_ptr->collection[i];
		//unsigned char *packed_sz_str=(unsigned char *)strchr((char *)((redisReply *)collection_ptr->collection[i])->str,  ':');
		unsigned char *packed_sz_str=(unsigned char *)strchr((char *)redis_ptr_indexed->str,  ':');
		if (IS_PRESENT(packed_sz_str))
		{
			*packed_sz_str='\0'; //axe the ':'
			unsigned char *packed_msg=++packed_sz_str;
			packed_sz_str=(unsigned char *)redis_ptr_indexed->str; //repoint to the begining of the original str the '0' will taper it to the size

			if (strlen((char *)packed_sz_str)<=UINT64_LONGEST_STR_SZ)
			{
				void 		*envelope_payload;
				size_t	envelope_payload_sz;

				packed_sz		= strtol((char *)packed_sz_str, NULL, 10);//size of the WebSocket message stored in redis
				websocket_msg_ptr=web_socket_message__unpack(NULL, packed_sz, packed_msg);
				if(IS_PRESENT(websocket_msg_ptr))
				{
					switch (websocket_msg_ptr->type)
					{
						case WEB_SOCKET_MESSAGE__TYPE__REQUEST:
							envelope_payload=websocket_msg_ptr->request->body.data;
							envelope_payload_sz=websocket_msg_ptr->request->body.len;
							break;
						case WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
							envelope_payload=websocket_msg_ptr->response->body.data;
							envelope_payload_sz=websocket_msg_ptr->response->body.len;
							break;

						default:
							web_socket_message__free_unpacked (websocket_msg_ptr, NULL);
							syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: UNRECOGNISED WESOCKETMESSAGE TYPE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);

							if (flag_delete_item) freeReplyObject(redis_ptr_indexed);
							continue;

					}

					unsigned char envelope_b64buf[GetBase64BufferAllocationSize(envelope_payload_sz)];
					if (base64_encode((const unsigned char *)envelope_payload, envelope_payload_sz, envelope_b64buf))
					{
						jobj_envelope=json_object_new_object();
						json_object_object_add (jobj_envelope,"message", json_object_new_string((const char *)envelope_b64buf));
						json_object_array_add(jobj_messages_array, jobj_envelope);

						processed_sz++;
					}
					else
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: COULD NOT B64 ENCODE ENVELOPE CONTENT", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);
					}

					web_socket_message__free_unpacked (websocket_msg_ptr, NULL);
				}//websocket present

			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu', packed_sz:'%lu'): ERROR: ERRENUOUS PACKED MSG SIZE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i, strlen((char *)packed_sz_str));
			}

			if (flag_delete_item)	freeReplyObject(redis_ptr_indexed);
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu', idx:'%lu'): ERROR: COULD NOT PARSE PACKED MSG SIZE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, i);
		}
	}//for

	if (processed_sz>0)
	{
		jobj_messages=json_object_new_object();
		json_object_object_add(jobj_messages,"messages", jobj_messages_array);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu', set_sz:'%lu', processed_set_sz:'%lu'): PROCESSED MESSAGES",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid, collection_ptr->collection_sz, processed_sz);
#endif

		_RETURN_RESULT_SESN(sesn_ptr_carrier, jobj_messages, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	return_error_empty_set:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid'%lu', userid:'%lu'): ERROR: RECEIVED EMPTY SET",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), userid);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, rescode);

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
	int rescode;

	if (redis_ptr_raw_messages->elements==0)	return 0;

	size_t 				i,
								processed_sz=0;
	PersistanceBackend	*pers_ptr	= SESSION_USRMSG_CACHEBACKEND(sesn_ptr);

	for (i=0; i < redis_ptr_raw_messages->elements; ++i)
	{
		(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_GET, userid, (char *)redis_ptr_raw_messages->element[i]->str);
	}

	size_t commands_processed=0;
	redisReply	**replies=replies_out;

	for (i=0; i<redis_ptr_raw_messages->elements; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[commands_processed])) != REDIS_OK)
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, userid);

			//TODO: we should probably abort if we ever get a NULL
			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL))
			{
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

	redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_GETALL, userid);

	if (unlikely(IS_EMPTY(redis_ptr))) 	{rescode=RESCODE_BACKEND_CONNECTION; 		goto return_error_backend_connection;}
	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_error_reply;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_error_nil;

	if (redis_ptr->elements==0)
	{
		rescode=RESCODE_BACKEND_DATA_EMPTYSET;

#ifdef __UF_FULLDEBUG
			  	 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, cid:'%lu', uid:'%lu'): NOTICE: EMPTY SET FOR USER STAGED MESSAGES",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);
#endif

		goto return_success;
	}

	rescode=RESCODE_BACKEND_DATA;

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

	if (msg_opts==MSGOPT_GET_REM_FIRST)
			return GetRemStagedMessageCacheRecordForIntraCommand(sesn_ptr, msg_desc_ptr,  payload_name, msg_opts);
	if (msg_opts==MSGOPT_GET_FIRST || msg_opts==MSGOPT_GET_LAST || msg_opts==MSGOPT_GETALL || msg_opts==MSGOPT_GETNAMED)
			return GetStagedMessageCacheRecordForIntraCommand (sesn_ptr, msg_desc_ptr, payload_name, msg_opts);
	if (msg_opts==MSGOPT_REMOVE) ;//TODO IMPLEMENT

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
GetRemStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr_carrier, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name, enum StoredMessageOptions msg_opts)
{
	int 		rescode										= RESCODE_PROG_NULL_POINTER;

	if (unlikely(IS_EMPTY(sesn_ptr_carrier)))			goto return_generic_error;
	//if (unlikely(IS_EMPTY(storage_id)))		goto return_final;

	const char 					*command_template_get,
											*command_template_rem;
	PersistanceBackend	*pers_ptr	= sesn_ptr_carrier->usrmsg_cachebackend;
	redisReply 					*redis_ptr;

	if (msg_opts==MSGOPT_GET_REM_FIRST)
	{
		command_template_get=REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST;
		command_template_rem=REDIS_CMD_INTRAMESSAGE_LIST_REM_EARLIEST;
	}
	else if (msg_opts==MSGOPT_GET_REM_LAST)
	{
		command_template_get=REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST;
		command_template_rem=REDIS_CMD_INTRAMESSAGE_LIST_REM_EARLIEST;
	}
	else if (msg_opts==MSGOPT_GET_REM_ALL) goto return_generic_error;//TODO IMPLEMENT

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), command_template_get, msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), command_template_rem, msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, SESSION_USRMSG_CACHEBACKEND(sesn_ptr_carrier), "EXEC");

	#define COMMAND_SET_SIZE	4
	#define EXEC_COOMAND_IDX (COMMAND_SET_SIZE-1)

	size_t					commands_successful	= COMMAND_SET_SIZE;
	redisReply			*replies[COMMAND_SET_SIZE]; memset (replies, 0, sizeof(replies));

	for (size_t i=0; i<COMMAND_SET_SIZE; i++)
	{
		if ((RedisGetReply(sesn_ptr_carrier, pers_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			--commands_successful;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, i);
			}
		}
	}//for

	if (unlikely(commands_successful!=COMMAND_SET_SIZE))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NOT ALL COMMAND SUCCESSED: REVOING TRANSACTION", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid);

		for (size_t i=0; i<COMMAND_SET_SIZE; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//remove replies upto  EXEC
	for (size_t i=0; i<COMMAND_SET_SIZE-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

	if (unlikely(IS_EMPTY(replies[EXEC_COOMAND_IDX])))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE FOR EXEC ELEMENT", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

#define GET_COMMAND_IDX	0
#define REM_COMMAND_IDX 1

	if (likely(replies[EXEC_COOMAND_IDX]->elements==COMMAND_SET_SIZE-2))
	{
		if (replies[EXEC_COOMAND_IDX]->element[GET_COMMAND_IDX]->elements==1)//this contains the payload in redis array
		{
			if (replies[EXEC_COOMAND_IDX]->element[REM_COMMAND_IDX]->integer==1)
			{
				return_success:
				_RETURN_RESULT_SESN(sesn_ptr_carrier, replies[EXEC_COOMAND_IDX], RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
			}
		}

		goto return_error_exec_command;
	}

	return_error_exec_command:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', reqid:'%lu', rem_redis_int:'%llu'): ERROR: EXEC command error", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), msg_desc_ptr->instance_descriptor_ptr->reqid, replies[EXEC_COOMAND_IDX]->element[REM_COMMAND_IDX]->integer);
	freeReplyObject(replies[EXEC_COOMAND_IDX]);
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL);

	return_generic_error:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL);


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

	if (msg_opts==MSGOPT_GETNAMED)
	{
		size_t	command_buf_sz=strlen(payload_name)+strlen(command_template)+10;
		char 		command_buf[command_buf_sz];

		snprintf(command_buf, command_buf_sz, command_template,
						 msg_desc_ptr->instance_descriptor_ptr->server_class, msg_desc_ptr->instance_descriptor_ptr->ufsrv_geogroup);
		redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_buf);
	}
	else
	{
		redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), command_template,
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

