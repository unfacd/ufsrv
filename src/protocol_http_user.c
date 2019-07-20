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
#include <pthread.h>
#include <json/json.h>
#include <user_backend.h>
#include <users.h>
#include <users_proto.h>
#include <session.h>
#include <fence.h>
#include <fence_proto.h>
#include <persistance.h>
#include <sessions_delegator_type.h>
#include <http_request.h>
#include <protocol_http.h>
#include <protocol_http_user.h>
#include <ufsrvuid.h>

static inline UFSRVResult *_GetAffectedInvitedFencesList (Session *sesn_ptr, unsigned long call_flags, CollectionDescriptor *collection_ptr_in);
static inline UFSRVResult *_GetAffectedMemberFencesList (Session *sesn_ptr, unsigned long call_flags, CollectionDescriptor *collection_ptr_in);
static inline UFSRVResult *_ClearBackendSessionCache (Session *sesn_ptr, unsigned long call_flags, FencesCollectionForSession *fence_collection_ptr_in);

/**
 * This file contains routines for general user manipulation for the ufsrvapi (http) implementation of ufsrv
 */

/**
 * 	@brief: Marshals an IntraCommand to deactivate a user. The most crucial part is propogating the command through the messaging queue
 * 	so all local Session instances held across all ufsrv instances are deleted and fences updated accordingly.
 *
 * 	We have to clear the backend cache here as we cannot guarantee execution by an ufsrv instance,since may not have any
 * 	active connection.
 *
 * 	@param sesn_ptr_carrier: this is not the actual connected Session for the user, just a carrier Session for the actual user,
 * 	yet this Session has full backend context.
 *
 * 	@dynamic_memory: IMPORTS 2x 'FenceEvents **' which get deallocated locally
 *
 */
UFSRVResult *
DeactivateUserAndPropogate (Session *sesn_ptr_carrier, UfsrvUid *uid_ptr, bool flag_nuke)
{
	UFSRVResult *res_ptr = DbAccountDeactivate (sesn_ptr_carrier, uid_ptr, flag_nuke);

	//not we not load fences list for user
	bool lock_already_owned = false;
	GetSessionForThisUserByUserId (sesn_ptr_carrier, UfsrvUidGetSequenceId(uid_ptr), &lock_already_owned, CALL_FLAG_LOCK_SESSION|CALL_FLAG_SEARCH_BACKEND|CALL_FLAG_REMOTE_SESSION);
	InstanceHolderForSession *instance_sesn_ptr_deactivated = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

	if (!IS_EMPTY(instance_sesn_ptr_deactivated)) {
		FenceEvent	**fence_events					=	NULL,
								**fence_events_invited	=	NULL;

		FencesCollectionForSession	*fences_collection_ptr	=	NULL;
		FencesCollectionForSession	fences_collection				=	{0};

    Session *sesn_ptr_deactivated = SessionOffInstanceHolder(instance_sesn_ptr_deactivated);

		SessionTransferAccessContext (sesn_ptr_carrier, sesn_ptr_deactivated, 0);
		_ClearBackendSessionCache (sesn_ptr_deactivated, CALLFLAGS_EMPTY, &fences_collection);

		//retrieve list of fences affected by deactivation as this contain eventids
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_deactivated)) {
			fences_collection_ptr = (FencesCollectionForSession *)SESSION_RESULT_USERDATA(sesn_ptr_deactivated);
			fence_events = (FenceEvent **)fences_collection_ptr->member_fences.collection;
			fence_events_invited = (FenceEvent **)fences_collection_ptr->invited_fences.collection;
		}

		CollectionDescriptor member_fences_collection		=	{0};
		CollectionDescriptor invited_fences_collection	=	{0};

		MakeFenceRecordsListFromFenceEventsInProto (sesn_ptr_deactivated, fence_events,			fences_collection_ptr->member_fences.collection_sz, 0, &member_fences_collection);
		MakeFenceRecordsListFromFenceEventsInProto (sesn_ptr_deactivated, fence_events_invited,	fences_collection_ptr->invited_fences.collection_sz, 0, &invited_fences_collection);

		SessionMessage session_msg				= SESSION_MESSAGE__INIT;
		CommandHeader		header						=	COMMAND_HEADER__INIT;

		session_msg.header								=	&header;
		MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr_deactivated), &(header.ufsrvuid), true); header.has_ufsrvuid=1;
		header.when												=	time(NULL);														header.has_when=1;

		session_msg.target_session				= SESSION_ID(sesn_ptr_deactivated);
		session_msg.status								= SESSION_MESSAGE__STATUS__INVALIDTED;
		session_msg.fences								= (FenceRecord **)member_fences_collection.collection;
		session_msg.n_fences							= member_fences_collection.collection_sz;
		session_msg.fences_invited				= (FenceRecord **)invited_fences_collection.collection;
		session_msg.n_fences_invited			= invited_fences_collection.collection_sz;

		UfsrvApiIntraBroadcastMessage (sesn_ptr_deactivated, _WIRE_PROTOCOL_DATA((&session_msg)), MSGCMD_SESSION, INTRA_WITH_INTER_SEMANTICS, NULL);

		if (!(IS_EMPTY(fence_events))) {
			free (fence_events[0]);
			free(fence_events);
		}

		if (!(IS_EMPTY(fence_events_invited))) {
			free (fence_events_invited[0]);
			free(fence_events_invited);
		}

		//this returns session to TypePool
		ClearLocalSessionCache (instance_sesn_ptr_deactivated, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_UNLOCK_SESSION);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief Helper function that clears the cached data for a given user on the backend. Local Session'data data image must be intact, reflecting most
 * 	up to date view of the user's state Session and Fence's wise.
 *
 *	 *	@param collection_ptr_in: a return carrier object to carry returned collection. Otherwise a dynamic collection is created and returned
 *
 * 	@lockd sesn_ptr: must be locked by caller
 *
 *	@dynamic_memory FenceEvent **: EXPORTS. Individual items in the returned collection may contain null references
 * 	@locks: None
 */
static inline UFSRVResult *
_GetAffectedInvitedFencesList (Session *sesn_ptr, unsigned long call_flags, CollectionDescriptor *collection_ptr_in)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	return _ufsrv_result_generic_error;

	size_t				actually_processed=0;
	PersistanceBackend	*pers_ptr=sesn_ptr->persistance_backend;

	CollectionDescriptor fence_collection={0};
	CollectionDescriptor *fence_collection_ptr __attribute__((unused)) ;

	//fence ids returend
	fence_collection_ptr=GetFenceCollectionForUser (sesn_ptr, &fence_collection, NULL, INVITED_FENCES);

	unsigned long	*fence_ids=(unsigned long *)fence_collection.collection;
	size_t			i=0;

	if (fence_collection.collection_sz==0)
	{
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	//Generate leave events for each of the identified fences
	FenceEvent **fence_events=calloc(fence_collection.collection_sz, sizeof(FenceEvent *));
	for (i=0; i<fence_collection.collection_sz; i++)
	{
		//this may contain null references
		fence_events[i]=BackendUpdateFenceEvent (sesn_ptr, &((FenceIdentifier){fence_ids[i], NULL}), NULL, EVENT_TYPE_FENCE_USER_UNINVITED);
	}

	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	for (; i<fence_collection.collection_sz; i++)
	{
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM, fence_ids[i], SESSION_USERID(sesn_ptr), SESSION_USERNAME(sesn_ptr));

#if __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', idx:'%lu'}: Processing FenceCollection item...", __func__, pthread_self(), sesn_ptr, fence_ids[i], i);
#endif
	}
	(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");

	actually_processed=fence_collection.collection_sz+2;
	redisReply	**replies=calloc(actually_processed, sizeof(redisReply *));

	//TODO: we need error recover for intermediate errors
	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK))
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd_idx:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, i);

			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL))
			{
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, SESSION_PID(sesn_ptr), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}
		}

		if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
	}//for

	free(replies);

	CollectionDescriptor *collection_ptr=NULL;

	if (!(IS_EMPTY(collection_ptr_in)))	collection_ptr=collection_ptr_in;
	else collection_ptr=malloc(sizeof(CollectionDescriptor));

	collection_ptr->collection=(void **)fence_events;
	collection_ptr->collection_sz=fence_collection.collection_sz;

	DestructFenceCollection (&fence_collection, false);

	_RETURN_RESULT_SESN(sesn_ptr, collection_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}

/**
 * 	@brief Clears the cached data for the given Session on the backend. Local Session'data data image must be intact, reflecting most
 * 	up to date view of the user's state Session and Fence's wise.
 *
 * 	@lockd sesn_ptr: must be locked by caller
 *
 *	@dynamic_memory FenceEvent **: EXPORTS
 * 	@locks: None
 */
static inline
UFSRVResult *
_GetAffectedMemberFencesList (Session *sesn_ptr, unsigned long call_flags, CollectionDescriptor *collection_ptr_in)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	return _ufsrv_result_generic_error;

	size_t				actually_processed=0;
	PersistanceBackend	*pers_ptr=sesn_ptr->persistance_backend;

	CollectionDescriptor	fence_collection={0};
	CollectionDescriptor	*fence_collection_ptr __attribute__((unused));

	fence_collection_ptr=GetFenceCollectionForUser (sesn_ptr, &fence_collection, NULL, MEMBER_FENCES);

	size_t			i;
	unsigned long	*fence_ids=(unsigned long *)fence_collection.collection;

	if (fence_collection.collection_sz==0)
	{
		//no need as we get no allocation upon empty set
		//if (!(IS_EMPTY(fence_collection_ptr)))	DestructFenceCollection (&fence_collection, false);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	//Generate leave events for each of the identified fences
	FenceEvent **fence_events=calloc(fence_collection.collection_sz, sizeof(FenceEvent *));
	for (i=0; i<fence_collection.collection_sz; i++)
	{
		//this may contain null references
		fence_events[i]=BackendUpdateFenceEvent (sesn_ptr, &((FenceIdentifier){fence_ids[i], NULL}), NULL, EVENT_TYPE_FENCE_USER_PARTED);
	}

	//prepare for removal of user from affected fences
	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	for (i=0; i<fence_collection.collection_sz; i++)
	{
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_FENCE_USERS_LIST_REM, fence_ids[i], SESSION_USERID(sesn_ptr));

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', idx:'%lu'}: Processing FenceCollection item...", __func__, pthread_self(), sesn_ptr, fence_ids[i], i);
#endif
	}
	(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");


	actually_processed=fence_collection.collection_sz+2;
	redisReply	**replies=calloc(actually_processed, sizeof(redisReply *));

	//TODO: we need error recover for intermediate errors
	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK))
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd_idx:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, i);

			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL))
			{
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, SESSION_PID(sesn_ptr), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}
		}

		if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
	}//for

	free(replies);

	//store and return leave events for affected fences
	CollectionDescriptor *collection_ptr=NULL;

	if (!(IS_EMPTY(collection_ptr_in)))	collection_ptr=collection_ptr_in;
	else collection_ptr=malloc(sizeof(CollectionDescriptor));

	collection_ptr->collection=(void **)fence_events;
	collection_ptr->collection_sz=fence_collection.collection_sz;

	DestructFenceCollection (&fence_collection, false);


	_RETURN_RESULT_SESN(sesn_ptr, collection_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}

/**
 * 	@brief Clears the cached data for the given Session on the backend. Local Session'data data image must be intact, reflecting most
 * 	up to date view of the user's state Session and Fence's wise.
 *
 *	@param sesn_ptr: User session with full access context
 *
 * 	@lockd sesn_ptr: must be locked by caller
 *
 *	@dynamic_memory FenceEvent **: EXPORTS
 * 	@locks: None
 */
static inline UFSRVResult *
_ClearBackendSessionCache (Session *sesn_ptr, unsigned long call_flags, FencesCollectionForSession *fence_collection_ptr_in)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	return _ufsrv_result_generic_error;

	size_t				actually_processed=0;
	PersistanceBackend	*pers_ptr=sesn_ptr->persistance_backend;

	FencesCollectionForSession *fences_collection_ptr;
	if (IS_EMPTY(fence_collection_ptr_in))	fences_collection_ptr=calloc(1, sizeof(FencesCollectionForSession));
	else									fences_collection_ptr=fence_collection_ptr_in;

	_GetAffectedMemberFencesList(sesn_ptr, call_flags, &(fences_collection_ptr->member_fences));
	_GetAffectedInvitedFencesList(sesn_ptr,  call_flags, &(fences_collection_ptr->invited_fences));


	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr,  REDIS_CMD_COOKIE_SESSION_DEL, SESSION_COOKIE(sesn_ptr));

	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_USERNAME_USERID_MAPPING_DEL, SESSION_USERNAME(sesn_ptr));

	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_USER_SESSION_RECORD_DEL_ALL, SESSION_USERID(sesn_ptr));

	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_USER_FENCE_LIST_REM_ALL, SESSION_USERID(sesn_ptr));

	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_MY_FENCE_INVITED_USERS_REM_ALL, SESSION_USERID(sesn_ptr));

	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_NICKNAMES_DIRECTORY_DEL, SESSION_USERNICKNAME(sesn_ptr)?SESSION_USERNICKNAME(sesn_ptr):"");
	(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");
	actually_processed=8;

	size_t 		i;
	redisReply	**replies;

	replies = calloc(actually_processed, sizeof(redisReply *));
	//TODO: we need error recover for intermediate errors
	for (i=0; i<actually_processed; i++) {
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK)) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd_idx:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, i);

			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, SESSION_PID(sesn_ptr), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}
		}

		if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
	}//for

	free(replies);

	_RETURN_RESULT_SESN(sesn_ptr, fences_collection_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}

/**
 * @dynamic_memory: INTERNALLY ALLOCATED AND FREED
 * @worker:
 * @returns: on success 0, otherwise -1
 *
 * @testing: To trick the enduser device into voice based verification, use the mock version of the settings. This will cause the
 * this function to return true without actually sending the sms, causing the device to timeout and launch into voice based verification.
 * There 3 spots where that needs to take place.
 *
 * curl -XPOST https://api.twilio.com/2010-04-01/Accounts/ACbbcaa406402345460e8548c62feddcb4/SMS/Messages.json \
    -d "Body=All%20in%20the%20game%2C%20yo" \
    -d "To=%2B+61xxxxx" \
    -d "From=%2B61428260161" \
    -u 'ACbbcaa406402345460e8548c62feddcb4:1992f069e83d4a605635a742e4b4f77a'

    {"sid": "SM20e73e32b298426389e1a763c85d1ef2", "date_created": "Tue, 17 May 2016 10:31:17 +0000",
    "date_updated": "Tue, 17 May 2016 10:31:17 +0000", "date_sent": null, "account_sid": "ACbbcaa406402345460e8548c62feddcb4",
    "to": "+61xxxxx", "from": "+61428260161", "body": "All in the game, yo", "status": "queued", "direction": "outbound-api",
    "api_version": "2010-04-01", "price": null, "price_unit": "USD",
    "uri": "/2010-04-01/Accounts/ACbbcaa406402345460e8548c62feddcb4/SMS/Messages/SM20e73e32b298426389e1a763c85d1ef2.json",
    "num_segments": "1"}

    regex ^\+?[1-9]\d{1,14}$ to validate format

    error resposne:
    { "code": 21614, "message": "To number: +611077501650, is not a mobile number", "more_info": "https:\/\/www.twilio.com\/docs\/errors\/21614", "status": 400 }'

    MOCK ACCOUNT
    curl -XPOST https://api.twilio.com/2010-04-01/Accounts/AC664997910a46ba8462e375b722be0962/Messages.json \
    -d "Body=All%20in%20the%20game%2C%20yo" \
    -d "To=%2B14108675309" \
    -d "From=%2B15005550006" \
    -u 'AC664997910a46ba8462e375b722be0962:f95bac24c1e54915d86adc36a6366284'
 */
int SendVerificationSms (Session *sesn_ptr, const char *destination, VerificationCode *vcode_ptr, bool android_sms_retriever_flag)
{
	static const char *provider_url_str=APIURL_SMS_PROD;
//	static const char *provider_url_str=APIURL_SMS_PROD;

	char *post_fields_str=NULL;
	char verification_code_str[8];

	if (android_sms_retriever_flag) {
    //fTdsb4yWQqP: one off generation for android only. Refer to AppSignatureHelper class in client code
    asprintf(&post_fields_str, "Body=<#>Your verification code: %s\n\nfTdsb4yWQqP&To=%s&From=%s", vcode_ptr->code_formatted, destination, API_FROM_SMSVOICE_PROD);//real
    //asprintf(&post_fields_str, "Body=<#>Your verification code: %s\n\nfTdsb4yWQqP&To=%s&From=%s",  vcode_ptr->code_formatted, destination, API_FROM_SMSVOICE_MOCK);//moc
  } else {
    asprintf(&post_fields_str, "Body=Your verification code: %s&To=%s&From=%s", vcode_ptr->code_formatted, destination, API_FROM_SMSVOICE_PROD);
    //asprintf(&post_fields_str, "Body=Your verification code: %s&To=%s&From=%s",  vcode_ptr->code_formatted, destination, API_FROM_SMSVOICE_MOCK);
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): Formatted post fields '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), post_fields_str);
#endif

	HttpRequestContext *http_ptr=GetHttpRequestContext(sesn_ptr);

	int result=HttpRequestPostUrl(http_ptr, provider_url_str, post_fields_str, APITOKEN_SMSVOICE_PROD, NULL, 0L);
			//APITOKEN_SMSVOICE_MOCK, NULL, 0L);
	if (result==0) {
		syslog(LOG_ERR, "%s (cid='%lu'): ERROR: COULD NOT POST URL '%s'", __func__, SESSION_ID(sesn_ptr), post_fields_str);

		free (post_fields_str);

		return -1;
	}

	free (post_fields_str);

	//we rely on the fact that SessionServiceGetUrl above has invoked the reset routine simple html buffer fetch
	do
	{
		http_ptr->jobj=json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
	}
	while ((http_ptr->jerr=json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

	if (http_ptr->jerr!=json_tokener_success)
	{
		syslog(LOG_NOTICE, "%s (pid='%lu' cid='%lu'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr),
		 json_tokener_error_desc(http_ptr->jerr));

		//no cleanup necessary we rely on subsequent get url invoking reset
		//free (post_fields_str); //done above
		return -2;
	}
	else
	{
		//onst char *str=json_object_to_json_string(ubawp_ptr->jobj);
		//syslog (LOG_DEBUG, "%s (pid='%lu' cid='%lu'): JSON resposne: '%s'", __func__,
										//pthread_self(), sesn_ptr->session_id, str);
		//success result are in ubawp_ptr->jobj
		//return 1;
	}

	const char *status=json_object_get_string(json__get(http_ptr->jobj, "status"));
	if (status)
	{
		if (strcmp(status, "queued")==0)
		{
			syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): RECEIVED SMS STATUS: '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), status);

			//verification sms was sent
			//BackendSetAuthenticationMode (sesn_ptr, "authmode", 4);

			return 0;
		}
		else
		{
			const char *str=json_object_to_json_string(http_ptr->jobj);
			syslog (LOG_DEBUG, "%s (pid='%lu' cid='%lu'): JSON response: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), str);
		}
	}

	return -1;

}

/**
 *  MOCK
 *  curl -XPOST https://api.twilio.com/2010-04-01/Accounts/AC664997910a46ba8462e375b722be0962/Calls.json \
    --data-urlencode "Url=http://demo.twilio.com/docs/voice.xml" \
    --data-urlencode "To=+61xxxxx" \
    --data-urlencode "From=+15005550006" \
    -u 'AC664997910a46ba8462e375b722be0962:f95bac24c1e54915d86adc36a6366284'

    REAL
    curl -XPOST https://api.twilio.com/2010-04-01/Accounts/ACbbcaa406402345460e8548c62feddcb4/Calls.json \
    --data-urlencode "Url=https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/Script/123456" \
    --data-urlencode "To=+61xxxxx" \
    --data-urlencode "From=+61428260161" \
    -u 'ACbbcaa406402345460e8548c62feddcb4:1992f069e83d4a605635a742e4b4f77a'
 */
int SendVerificationVoice (Session *sesn_ptr, const char *destination, VerificationCode *vcode_ptr)
{
	static const char *provider_url_str=APIURL_VOICE_PROD;
	//static const char *provider_url_str=APIURL_VOICE_MOCK;

	char *post_fields_str=NULL;
	char verification_code_str[8];

	asprintf(&post_fields_str, "Url=https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/Script/%lu&To=%s&From=%s",  vcode_ptr->code, destination, API_FROM_SMSVOICE_PROD);
	//asprintf(&post_fields_str, "Url=https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/Script/%lu&To=%s&From=%s",  vcode_ptr->code, destination, API_FROM_SMSVOICE_MOCK);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): Formatted post fields '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), post_fields_str);
#endif

	HttpRequestContext *http_ptr=GetHttpRequestContext(sesn_ptr);

	int result=HttpRequestPostUrl(http_ptr, provider_url_str, post_fields_str, APITOKEN_SMSVOICE_PROD, NULL, 0L);
	//int result=HttpRequestPostUrl(http_ptr, provider_url_str, post_fields_str, APITOKEN_SMSVOICE_MOCK, NULL, 0L);
	if (result==0) {
		syslog(LOG_ERR, "%s (cid='%lu'): ERROR: COULD NOT POST URL '%s'", __func__, SESSION_ID(sesn_ptr), post_fields_str);

		free (post_fields_str);

		return -1;
	}

	free (post_fields_str);

	do {
		http_ptr->jobj=json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
	} while ((http_ptr->jerr=json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

	if (http_ptr->jerr!=json_tokener_success) {
		syslog(LOG_NOTICE, "%s (pid='%lu' cid='%lu'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_tokener_error_desc(http_ptr->jerr));

		return -2;
	}

	const char *status=json_object_get_string(json__get(http_ptr->jobj, "status"));
	if (status) {
		if (strcmp(status, "queued")==0) {
			syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): RECEIVED SMS STATUS: '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), status);

			return 0;
		} else {
			const char *str=json_object_to_json_string(http_ptr->jobj);
			syslog (LOG_DEBUG, "%s (pid='%lu' cid='%lu'): JSON response: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), str);
		}
	}

	return -1;

}

int
SendVerificationEmail (Session *sesn_ptr, const char *to_email, const PendingAccount *pacct_ptr)
{
/* https://documentation.mailgun.com/en/latest/api-sending.html#examples
 * curl -s --user 'api:key-xxxx' \
    https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages \
    -F from='Registration <info@unfacd.com>' \
    -F to=x@ccc.com \
    -F subject='Hello' \
    -F text='Testing some Mailgun awesomeness!'

 reply
 {
  "id": "<20190324122202.1.A931674C6AF4236A@ufsrv.unfacd.io>",
  "message": "Queued. Thank you."
}%
 */
	static const char *provider_url_str=API_EMAIL_URL;//real

	char *post_fields_str=NULL;
	char verification_code_str[8];

	asprintf (&post_fields_str, "from=unfacd registration service <info@unfacd.com>"
														 "&to=%s"
							 "&subject=Verify your unfacd registration"
							 "&html=<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>unfacd registration verification</title><link href=\"http://unfacd.com/ufsrv/css/normalize.css\" rel=\"stylesheet\"><link rel=\"icon\" href=\"http://unfacd.com/ufsrv/images/favicon.png\" /></head><body><p>Click this <a href=\"https://api.unfacd.io/V1/Account/VerifyStatus/%s/%lu\">link</a> to verify your registration.</p> <p>If you can't see the link copy and paste this url to your browser: https://api.unfacd.io/V1/Account/VerifyStatus/%s/%lu</p> <p>Please note this link is only valid for less than 12 hours. Thank you.</p><script src=\"https://ajax.googleapis.com/ajax/libs/jquery/2.1.4/jquery.min.js\"></script></body></html>"
				"&text=Click on this link https://api.unfacd.io/V1/Account/VerifyStatus/%s/%lu to verify your registration. Please note this link is only valid for less than 12 hours. \nThank you.",
														 to_email, pacct_ptr->cookie, pacct_ptr->verification_code.code, pacct_ptr->cookie, pacct_ptr->verification_code.code, pacct_ptr->cookie, pacct_ptr->verification_code.code);


#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): Formatted post fields '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), post_fields_str);
#endif

	HttpRequestContext *http_ptr=GetHttpRequestContext(sesn_ptr);

	int result=HttpRequestPostUrl(http_ptr, provider_url_str, post_fields_str, API_EMAIL_KEY, NULL, 0L);
	if (result==0) {
		syslog(LOG_ERR, "%s (cid='%lu'): ERROR: COULD NOT POST URL '%s'", __func__, SESSION_ID(sesn_ptr), post_fields_str);

		free (post_fields_str);

		return -1;
	}

	free (post_fields_str);

	//we rely on the fact that SessionServiceGetUrl above has invoked the reset routine simple html buffer fetch
	do {
		http_ptr->jobj=json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
	} while ((http_ptr->jerr=json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

	if (http_ptr->jerr!=json_tokener_success) {
		syslog(LOG_NOTICE, "%s {pid:'%lu' cid:'%p'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), sesn_ptr, json_tokener_error_desc(http_ptr->jerr));

		//no cleanup necessary we rely on subsequent get url invoking reset
		return -2;
	}

	const char *message=json_object_get_string(json__get(http_ptr->jobj, "message"));
	if (IS_STR_LOADED(message)) {
		if (IS_PRESENT(strstr(message, "Queued."))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: RECEIVED EMAIL QUEUED CONFIRMATION STATUS: '%s' ", __func__, pthread_self(), sesn_ptr, json_object_get_string(json__get(http_ptr->jobj, "id")));

			return 0;
		} else {
			const char *str=json_object_to_json_string(http_ptr->jobj);
			syslog (LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: JSON response: '%s'", __func__, pthread_self(), sesn_ptr, str);
		}
	}

	return -1;
}
