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
#include <nportredird.h>
#include <ufsrvresult_type.h>
#include <thread_context_type.h>
#include <ufsrvuid.h>
#include <h_basic_auth.h>
#include <h_handler.h>
#include <request.h>
#include <response.h>
#include <ufsrv_core/user/user_backend.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_core/ratelimit/ratelimit.h>
#include <adt_locking_lru.h>
#include <recycler/recycler.h>

extern __thread ThreadContext ufsrv_thread_context;

struct onion_handler_auth_pam_data_t{
	char *realm;
	char *pamname;
	onion_handler *inside;
};

static HashTable 		BasicAuthHashTable;
static LockingLru 	BasicAuthLruCache;

//type recycler pool for BasicAuthDescriptor
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#if 1
//assigned when the typepool is initialised
static RecyclerPoolHandle *BasicAuthDescriptorPoolHandle;

static int	TypePoolInitCallback_BasicAuthDescriptor (ClientContextData *data_ptr, size_t oid);
static int	TypePoolGetInitCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int	TypePoolPutInitCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char	*TypePoolPrintCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int	TypePoolDestructCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *_PrintBasicAuthDescriptor (ClientContextData *item_ptr, size_t index);

static RecyclerPoolOps ops_basicauth_descriptor = {
		TypePoolInitCallback_BasicAuthDescriptor,
		TypePoolGetInitCallback_BasicAuthDescriptor,
		TypePoolPutInitCallback_BasicAuthDescriptor,
		TypePoolPrintCallback_BasicAuthDescriptor,
		TypePoolDestructCallback_BasicAuthDescriptor
};
#endif
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

inline static void _InitialiseBasicAuthHashTable (HashTable *hashtable_ptr, size_t hashtable_sz, unsigned long call_flags);
static BasicAuthDescriptor *_CacheLocalLruSetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long userid, BasicAuthDescriptor *basicauth_ptr_in);
static BasicAuthDescriptor *_CacheLocalLruGetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded);
static UFSRVResult *_CacheBackendSetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long userid);
static UFSRVResult *_CacheBackendGetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded);
static size_t _CacheLocalLruGetConfiguration (void);

void onion_handler_auth_pam_delete(onion_handler_auth_pam_data *d);

#define RESPONSE_UNAUTHORIZED "<h1>Unauthorized access</h1>"
#define RESPONSE_RATELIMIT_EXCEEDED "<h1>Rate limit exceeded</h1>"

static size_t
_CacheLocalLruGetConfiguration (void)
{
	extern ufsrv *const masterptr;

	lua_getglobal(LUA_CTX, "ufsrvapi_cache_authorisation");
	if (!lua_istable(LUA_CTX, -1)) {
			syslog(LOG_NOTICE, "%s: `ufsrvapi_cache_authorisation' is not a valid config table", __func__);
			return 1024;
	} else {
		//TODO: validate values
		return LUA_GetFieldToInteger("size");
		//sessions_delegator_ptr->user_timeouts.suspended=LUA_GetFieldToString("eviction_policy");
	}

	return 0;
}

void
InitialiseBasicAuthLruCache (void)
{
	size_t lrucache_sz = _CacheLocalLruGetConfiguration();
	if (lrucache_sz == 0) {
		lrucache_sz=_CONFIDEFAULT_HASHTABLE_BASICAUTH_SZ;
		syslog (LOG_NOTICE, "%s: NOTICE: Lru Cache Size for BasicAuth was incorrectly set: Using default value of: '%ld'", __func__, lrucache_sz);
	}

//	_InitialiseBasicAuthHashTable (lrucache_sz);
	InitBasicAuthDescriptorRecyclerTypePool ();
	InitLockingLruItemRecyclerTypePool ();
	InitLockingLru (&BasicAuthLruCache, "BasicAuth", lrucache_sz, &BasicAuthHashTable, _InitialiseBasicAuthHashTable, NULL, _PrintBasicAuthDescriptor);
}

inline static void
_InitialiseBasicAuthHashTable (HashTable *hashtable_ptr, size_t hashtable_sz, unsigned long call_flags)
{
	if (HashTableLockingInstantiate(hashtable_ptr, (offsetof(BasicAuthDescriptor, b64encoded)), KEY_SIZE_ZERO, HASH_ITEM_NOT_PTR_TYPE, "BasicAuth", NULL)) {
		HASHTABLE_CLEARFLAG(hashtable_ptr, flag_resizable);
		hashtable_ptr->max_size = hashtable_sz;

		syslog(LOG_INFO, "%s: SUCCESS: BasicAuth HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, hashtable_ptr->fKeyOffset, hashtable_ptr->fKeySize);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE BasicAuth HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}
}

/*
 * 	@brief:	Given basicauth user credentials look up the user  in lru cache first and where doesnt's existing subsequently
 * 	in backend cache, which causes the item to be fed into the lru cache. Does not query db backend.
 *
 * 	@dynamic_memory: IMPORTS and DEALLOCATES 'char *'
 * 	@returns: 0 on sucess and the userid returned in param
 */
int
CacheValidateBasicAuth (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long *return_userid)
{
	char 						*basicauth_decoded_backend	=	NULL;
	char 						*userid											=	NULL;
	unsigned long 	ret;
	unsigned long 	userid_converted;

	BasicAuthDescriptor *basicauth_ptr = _CacheLocalLruGetBasicAuthItem (sesn_ptr, basicauth_b64encoded);
	if (IS_PRESENT(basicauth_ptr)) {
		*return_userid = basicauth_ptr->userid;
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', basicauth_decoded:'%s', basicauth_decoded_backend:'%s'}: LRU CACHE HIT", __func__, pthread_self(), sesn_ptr, basicauth_ptr->userid, basicauth_ptr->decoded, basicauth_ptr->b64encoded);
#endif
		return 0;
	}

	_CacheBackendGetBasicAuthItem (sesn_ptr, basicauth_b64encoded);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		basicauth_decoded_backend = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
		if (IS_PRESENT(basicauth_decoded_backend)) {
			userid = strrchr (basicauth_decoded_backend, ':');	*userid = '\0';  userid++;

			if (IS_EMPTY(userid))	goto return_userid_error;

			if ((strcmp(basicauth_decoded, basicauth_decoded_backend) == 0)) {
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%s', basicauth_decoded:'%s', basicauth_decoded_backend:'%s'}: BasicAuth Successful", __func__, pthread_self(), sesn_ptr, userid, basicauth_decoded, basicauth_decoded_backend);
#endif

				return_success:
				userid_converted = strtoul(userid, NULL, 10);
				_CacheLocalLruSetBasicAuthItem (sesn_ptr, basicauth_b64encoded, basicauth_decoded, userid_converted, NULL);
				*return_userid = userid_converted;
				free (basicauth_decoded_backend);
				return 0;
			}
			else goto return_mismatch_error;
		}
	}

	goto return_backend_error;

	return_userid_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', basicauth_decoded:'%s', basicauth_decoded_backend:'%s'}: ERROR: BACKEND CACHED: COULD NOT ASCRETAIN USERID", __func__, pthread_self(), sesn_ptr, basicauth_decoded, basicauth_decoded_backend);
	ret = -3;
	goto return_free;

	return_mismatch_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%s', basicauth_decoded:'%s', basicauth_decoded_backend:'%s'}: ERROR: BACKEND CACHED basicauth_decoded DOESN NOT MATCH", __func__, pthread_self(), sesn_ptr, userid, basicauth_decoded, basicauth_decoded_backend);
	ret = -2;
	goto return_free;

	return_backend_error:
	ret = -1;
	goto return_error;

	return_free:
	free (basicauth_decoded_backend);

	return_error:
	return ret;
}

/**
 * 	@brief: Basic interface function for caching freshly authenticated basicauth value. S
 * 	We leave an extra room for a hidden reference to the Lrus list item corresponding with this BasicAuthDescriptor so we can derive them from
 * 	one another.
 */
static BasicAuthDescriptor *
_CacheLocalLruSetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long userid, BasicAuthDescriptor *basicauth_ptr_in)
{
	uintptr_t p;
	BasicAuthDescriptor *basicauth_ptr;
	BasicAuthDescriptor *evicted_item_ptr = NULL;

	if (IS_PRESENT(basicauth_ptr_in))	p = (uintptr_t)basicauth_ptr_in;
	else															p = (uintptr_t)calloc(1, sizeof(BasicAuthDescriptor) + sizeof(uintptr_t));//extra to store a pointer to list item reference

	basicauth_ptr = (BasicAuthDescriptor *)(p + (sizeof(uintptr_t)));

	strncpy (basicauth_ptr->b64encoded, basicauth_b64encoded, SMBUF-1);
	strncpy (basicauth_ptr->decoded, 		basicauth_decoded, SMBUF-1);
	basicauth_ptr->userid = userid;

	LruClientData *data_ptr_returned = LockingLruSet (&BasicAuthLruCache, sesn_ptr, (LruClientData *)basicauth_ptr);
	if	(IS_PRESENT(data_ptr_returned)) {
		if (data_ptr_returned != basicauth_ptr) {
#ifdef __UF_TESTING
			syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu', basicauth_uid_evicted:'%lu'): Evicted list item returned...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), ((BasicAuthDescriptor *)data_ptr_returned)->userid);
#endif

			free (data_ptr_returned - sizeof(uintptr_t));
		}
	} else {
		if (IS_EMPTY(basicauth_ptr_in))	free ((void *)p);

		return NULL;
	}

	return basicauth_ptr;

}

/**
 * 	@brief:	Basic interface for querying the local LruCache for the existence of a given basicauth value.
 * 	If item is present in the hash, the items is promoted to the front of the list, unless it is already at the head
 */
static BasicAuthDescriptor *
_CacheLocalLruGetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded)
{
	BasicAuthDescriptor *basicauth_ptr,
											*basicauth_ptr_evicted = NULL;

	basicauth_ptr = (BasicAuthDescriptor *)LockingLruGet (&BasicAuthLruCache, sesn_ptr, basicauth_b64encoded, (LruClientData **)&basicauth_ptr_evicted);

	return basicauth_ptr;

}

#define _REDISCMD_SET_BASICAUTH	"SET %s:%s %s:%lu EX %lu"
#define _REDISCMD_GET_BASICAUTH "GET %s:%s"

/**
 *	@dynamic_memory: EXPORTS 'char *'
 */
static UFSRVResult *
_CacheBackendGetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded)
{
	int 								rescode =  RESCODE_PROG_NULL_POINTER;
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr;

	if (unlikely((IS_EMPTY(basicauth_b64encoded))))		goto return_error_param;

	pers_ptr = sesn_ptr->persistance_backend;

	char command_buf[LBUF];
	snprintf(command_buf, LBUF-1, _REDISCMD_GET_BASICAUTH, _BASICAUTH_PREFIX,  basicauth_b64encoded);
	redis_ptr  = (*pers_ptr->send_command)(sesn_ptr, command_buf);

	if (IS_EMPTY(redis_ptr)) {
	  rescode = RESCODE_BACKEND_CONNECTION;
	  goto return_error_backend_connection;
	}

	if (redis_ptr->type == REDIS_REPLY_STRING) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', location:'%s'): Retrieved decoded basicauth...", __func__, pthread_self(), sesn_ptr, redis_ptr->str);
#endif
		char *basicauth_decoded_backend = strdup(redis_ptr->str);
		freeReplyObject(redis_ptr);

		 _RETURN_RESULT_SESN(sesn_ptr, basicauth_decoded_backend, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_error_backend_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_error_backend_nil;

	goto on_return_free;

	return_error_param:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "id or location");
	goto return_final;

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', basicauth_b64encoded:'%s'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, basicauth_b64encoded);
	goto return_final;

	return_error_backend_error:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', basicauth_b64encoded:'%s'): ERROR COULD NOT GET: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, basicauth_b64encoded, redis_ptr->str);
	goto on_return_free;

	return_error_backend_nil:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', basicauth_b64encoded:'%s'): ERROR COULD NOT GET: NIL REPLY ERROR", __func__, pthread_self(), sesn_ptr, basicauth_b64encoded);
	goto on_return_free;

	on_return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;
}

static UFSRVResult *
_CacheBackendSetBasicAuthItem (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long userid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))																									goto return_generic_error;
	if (unlikely((IS_EMPTY(basicauth_b64encoded)) || (IS_EMPTY(basicauth_decoded))))	goto return_error_param;

	int 								rescode = RESCODE_PROG_NULL_POINTER;
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr;

	pers_ptr = sesn_ptr->persistance_backend;

	char command_buf[LBUF];
	snprintf(command_buf, LBUF-1, _REDISCMD_SET_BASICAUTH,  _BASICAUTH_PREFIX, basicauth_b64encoded, basicauth_decoded, userid, _BASICAUTH_CACHE_EXPIRY);
	redis_ptr = (*pers_ptr->send_command)(sesn_ptr, command_buf);

	if (unlikely(IS_EMPTY(redis_ptr)))	goto	return_error_backend_connection;

	if (strcasecmp(redis_ptr->str, "ok") == 0) {

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	goto return_error_backend;

	return_error_param:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "id or location");
	goto return_final;

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', basicauth_b64encoded:'%s'): ERROR COULD ISSUE SET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, basicauth_b64encoded);
	goto return_final;

	return_error_backend:
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', basicauth_b64encoded:'%s'): ERROR SET _BASICAUTH FAILED: '%s' REPLY CODE:'%d'", __func__, pthread_self(), sesn_ptr, basicauth_b64encoded, redis_ptr->str, redis_ptr->type);

	on_return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

int
onion_handler_auth_pam_handler(InstanceHolderForSession *instance_sesn_ptr, onion_handler_auth_pam_data *d, onion_request *request, onion_response *res)
{
	const char *o								=	onion_request_get_header(request, "Authorization");
  const char *cookie					=	onion_request_get_header(request, HTTP_HEADER_COOKIE);
	char *auth									=	NULL;
	char *ufsrvuid							=	NULL;
	char *passwd								=	NULL;
  const char *basicauth_decoded = NULL;
	bool bypass_authentication	=false;
	bool signup_flag						=	false;

	Session *sesn_ptr           = SessionOffInstanceHolder(instance_sesn_ptr);

  //bypass list
  const char *path = onion_request_get_path(request);

  if (IS_PRESENT(path) && (strlen(path) <= XLBUF)) {
    if ((strcasecmp(path, 	"V1/Nonce"															) == 0) ||
        (strcasecmp(path, 	"V1/Account/New"												) == 0)	||
        (strcasecmp(path, 	"V1/Account/Captcha"										) == 0)	||
        /*(strncasecmp(path, 	"V1/Nickname/", 											12)==0)	||//this support pathparams*/
        (strncasecmp(path, 	"V1/Account/VerifyNew/Voice/Script/", 34) == 0)	||
        (strncasecmp(path,  "V1/Account/VerifyStatus/", 				  24) == 0)
       )

      goto exit_invoke_next_handler;

    //this endpoint contains username:password in signup capacity,ie new users, so we shouldn't attempt to authenticate; we just need the info
    if ((strcasecmp(path, "V1/Account/VerifyNew"									) == 0)		||
        (strncasecmp(path,"V1/Account/VerifyNew/Voice/", 				27) == 0)
    ) {
      signup_flag           = true;
      bypass_authentication = true;
    }
  } else {
    goto exit_not_authorised;
  }

	//Basic MTE6MTI=
	if (o && strncmp(o, "Basic", 5) == 0) {
		int len = 0;

		auth = (char *)base64_decode((unsigned char *)&o[6], strlen(&o[6]), &len);

		if (IS_EMPTY(auth))	goto	exit_not_authorised;

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG,"%s (pid:'%lu', cid:'%p'): RECEIVED BASIC AUTH: '%s'. DECODED: '%s'\n", __func__, pthread_self(), sesn_ptr, &o[6], auth);
#endif

		//retain a copy before it gets chopped up below, as we need it for comparing against stored backend value
		basicauth_decoded = strdupa(auth);
    ufsrvuid  = auth;

		int i     =0;
		while (auth[i] != '\0' && auth[i] != ':') i++;

		if (auth[i] == ':') {
			auth[i] = '\0'; // ensure i have user ready
			passwd = &auth[i+1];
		} else
			LOAD_NULL(passwd);
	}
	
	if (IS_PRESENT(ufsrvuid) && IS_PRESENT(passwd)) {
		int 									ok;
		unsigned long 				userid        = 0;
		UFSRVResult 					*res_ptr      = NULL;
		AuthenticatedAccount 	*authacct_ptr = NULL;

		if (signup_flag == false) {
			if ((ok = CacheValidateBasicAuth(sesn_ptr, &o[6], basicauth_decoded, &userid))==0)	bypass_authentication=true;
			else userid = 0;
		} else {
      SESSION_USERNAME(sesn_ptr) = strdup(ufsrvuid);//in this mode ufsrvuid may contain actual username used for rego signup. Special case for upgrading from pending account, where ufsrvuid is not known
		}

		if (bypass_authentication || signup_flag)	ok = 1;
		else {
      if (!IS_STR_LOADED(cookie)) goto exit_not_authorised;

			//bootstrap user from single source of truth
			if (userid == 0) {
			  //for first timeusers we won't be able to retrieve userid from cache, so we have to recreate it from provided username
			    userid = UfsrvUidGetSequenceIdFromEncoded(ufsrvuid);
      }

			res_ptr = DbAuthenticateUser (sesn_ptr, userid, passwd, cookie, CALLFLAGS_EMPTY);
			if (_RESULT_TYPE_SUCCESS(res_ptr)) {
				ok = 1;
				if (_RESULT_CODE_EQUAL(res_ptr, RESULT_CODE_USER_AUTHENTICATION)) {
					authacct_ptr	=	(AuthenticatedAccount *)_RESULT_USERDATA(res_ptr);
					userid				=	authacct_ptr->userid;
					memcpy(SESSION_UFSRVUID(sesn_ptr), authacct_ptr->ufsrvuid.data, CONFIG_MAX_UFSRV_ID_SZ);

					free (authacct_ptr->e164number);
					free(authacct_ptr->cookie);
					free(authacct_ptr->username);
					free(authacct_ptr);
				} else {
					userid=(unsigned long)_RESULT_USERDATA(res_ptr);
				}

				//seed item into two caches
				_CacheLocalLruSetBasicAuthItem (sesn_ptr, &o[6], basicauth_decoded, userid, NULL);
				_CacheBackendSetBasicAuthItem (sesn_ptr, &o[6], basicauth_decoded, userid);
			} else {
			  ok = 0;
			  if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_AUTHCOOKIE)) {
          syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', cookie:'%s'}: ERROR: AUTHENTICATION COOKIE INVALID", __func__, pthread_self(), userid, cookie);
			  }
			}
		}
		
		if (ok) {
      UfsrvUidCreateFromEncodedText(ufsrvuid, &(SESSION_UFSRVUIDSTORE(sesn_ptr)));

			SESSION_USERPASSWORD(sesn_ptr)	=	strdup(passwd);
      SESSION_USERID_TEMP(sesn_ptr)		=	userid;

			free(auth);

			if (IsRateLimitExceededForSession(THREAD_CONTEXT_USRMSG_CACHEBACKEND, userid, 0, RLNS_REQUESTS))	goto exit_ratelimit_exceeded;

			exit_invoke_next_handler:
			return onion_handler_handle(instance_sesn_ptr, d->inside, request, res);//AA+ sesn_ptr
		}
	}
	
	if (IS_PRESENT(auth))	free(auth);

	// Not authorized. Ask for it.
	exit_not_authorised:
	{
		char temp[256];


    syslog(LOG_DEBUG, "%s {pid:'%lu', basicauth:'%s', basicauth_decoded:'%s', cookie:'%s'}: ERROR: AUTHENTICATION FAILED (MAYBE PATH LENGTH EXCEEDED)", __func__, pthread_self(), basicauth_decoded?basicauth_decoded:"*", o?o:"*", cookie?cookie:"*");

		sprintf(temp, "Basic realm=\"%s\"", d->realm);
		onion_response_set_header(res, "WWW-Authenticate", temp);
		onion_response_set_code(res, HTTP_UNAUTHORIZED);
		onion_response_set_length(res, sizeof(RESPONSE_UNAUTHORIZED));

		onion_response_write(instance_sesn_ptr, res, RESPONSE_UNAUTHORIZED, sizeof(RESPONSE_UNAUTHORIZED));

		statsd_inc(sesn_ptr->instrumentation_backend, "api.basicauth.failed", 1.0);

		goto return_processed;
	}

	exit_ratelimit_exceeded:
	{
    syslog(LOG_DEBUG, "%s {pid:'%lu', basicauth:'%s', basicauth_decoded:'%s', cookie:'%s'}: ERROR: RATELIMIT EXCEEDED", __func__, pthread_self(), basicauth_decoded?basicauth_decoded:"*", o?o:"*", cookie?cookie:"*");

		onion_response_set_code(res, HTTP_RATELIMIT_EXCEEDED);
		onion_response_set_length(res,sizeof(RESPONSE_RATELIMIT_EXCEEDED));

		onion_response_write(instance_sesn_ptr, res, RESPONSE_RATELIMIT_EXCEEDED, sizeof(RESPONSE_RATELIMIT_EXCEEDED));

		statsd_inc(sesn_ptr->instrumentation_backend, "api.ratelimit", 1.0);

		goto return_processed;
	}

	return_processed:
	return OCS_PROCESSED;
}

void
onion_handler_auth_pam_delete(onion_handler_auth_pam_data *d)
{
	free(d->pamname);
	free(d->realm);
	onion_handler_free(d->inside);
	free(d);
}

/**
 * @short Creates an path handler. If the path matches the regex, it reomves that from the regexp and goes to the inside_level.
 *
 * If on the inside level nobody answers, it just returns NULL, so ->next can answer.
 */
onion_handler *onion_handler_auth_pam(const char *realm, const char *pamname, onion_handler *inside_level)
{
	onion_handler_auth_pam_data *priv_data=malloc(sizeof(onion_handler_auth_pam_data));
	if (!priv_data)	return NULL;

	priv_data->inside = inside_level;
	if (pamname)	priv_data->pamname = strdup(pamname);
	priv_data->realm = strdup(realm);
	
	onion_handler *ret = onion_handler_new((onion_handler_handler)onion_handler_auth_pam_handler, priv_data, (onion_handler_private_data_free) onion_handler_auth_pam_delete);

	return ret;
}

//----------- Recycer Type Pool BasicAuthDescriptor ---- //
void
InitBasicAuthDescriptorRecyclerTypePool ()
{
	#define _BasicAuthDescriptor_EXPANSION_THRESHOLD (1024*10)
  extern ufsrv *const masterptr;

	BasicAuthDescriptorPoolHandle = RecyclerInitTypePool("BasicAuthDescriptor",
                                                       sizeof(BasicAuthDescriptor) + sizeof(uintptr_t), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                                       _BasicAuthDescriptor_EXPANSION_THRESHOLD,
                                                       &ops_basicauth_descriptor);

	syslog(LOG_INFO, "%s: Initialised TypePool: '%s'. TypeNumber:'%d', Block Size:'%lu'", __func__, BasicAuthDescriptorPoolHandle->type_name, BasicAuthDescriptorPoolHandle->type, BasicAuthDescriptorPoolHandle->blocksz);
}

void
BasicAuthDescriptorIncrementReference (BasicAuthDescriptor *descriptor_ptr, int multiples)
{
	RecyclerTypeReferenced (2, (RecyclerClientData *)descriptor_ptr, multiples);
}

void
BasicAuthDescriptorDecrementReference (BasicAuthDescriptor *descriptor_ptr, int multiples)
{
	RecyclerTypeUnReferenced (2, (RecyclerClientData *)descriptor_ptr, multiples);
}

__pure unsigned
BasicAuthDescriptorPoolTypeNumber()
{
	unsigned  type=BasicAuthDescriptorPoolHandle->type;
	return type;
}

InstanceHolderForBasicAuthDescriptor *
BasicAuthDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags)
{
	InstanceHolderForBasicAuthDescriptor *instance_holder_ptr = RecyclerGet(BasicAuthDescriptorPoolTypeNumber(), ctx_data_ptr, call_flags);
	if (unlikely(IS_EMPTY(instance_holder_ptr)))	goto return_error;

	return instance_holder_ptr;

	return_error:
	syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), (void *)0, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get BasicAuthDescriptor instance");
	return NULL;

}

void
BasicAuthDescriptorReturnToRecycler (InstanceHolder *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
	RecyclerPut(BasicAuthDescriptorPoolTypeNumber(), instance_holder_ptr, (ContextData *)ctx_data_ptr, call_flags);
}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime. No InstanceHolder ref yet.
 *
 */
static int
TypePoolInitCallback_BasicAuthDescriptor (ClientContextData *data_ptr, size_t oid)
{
  BasicAuthDescriptor *descriptor_ptr = (BasicAuthDescriptor *)data_ptr;

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Get().
 */
static int
TypePoolGetInitCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  InstanceHolderForBasicAuthDescriptor *instance_descriptor_ptr = (InstanceHolderForBasicAuthDescriptor *)data_ptr;

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might havepassed to the recycler when we issued Put In this instance Fence *
 */
static int
TypePoolPutInitCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  InstanceHolderForBasicAuthDescriptor *instance_descriptor_ptr = (InstanceHolderForBasicAuthDescriptor *)data_ptr;

	return 0;//success
}

static char *
TypePoolPrintCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  InstanceHolderForBasicAuthDescriptor *instance_descriptor_ptr = (InstanceHolderForBasicAuthDescriptor *)data_ptr;

	return NULL;
}

static int
TypePoolDestructCallback_BasicAuthDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  InstanceHolderForBasicAuthDescriptor *instance_descriptor_ptr = (InstanceHolderForBasicAuthDescriptor *)data_ptr;

	return 0;//success

}

/**
 * @brief Default item printer for BasicAuthDescriptor LRU items
 * @param item_ptr ClientContextData-aliased and un-extracted BasicAuthDescriptor
 * @param index item iterator index position
 * @return
 */
static char *
_PrintBasicAuthDescriptor (ClientContextData *item_ptr, size_t index)
{
  BasicAuthDescriptor *basic_auth_ptr = (BasicAuthDescriptor *)item_ptr;
  syslog(LOG_ERR, "%s (pid:'%lu', uid:'%lu', idx:'%lu'): ListItem Client Data", __func__, pthread_self(), basic_auth_ptr->userid, index);

  return NULL;
}
////end typePool  /////////////////////
