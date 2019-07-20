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
#include <stdarg.h> //va
#include <time.h>
#include <redis.h>
#include <nportredird.h>
#include <sessions_delegator_type.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

static redisContext *ConnectRedisBackend(const struct BackendConfig *config);

static long long usec(void) __attribute__((unused));


static long long usec(void)
{
  struct timeval tv;

  gettimeofday(&tv,NULL);

  return (((long long)tv.tv_sec)*1000000)+tv.tv_usec;
}

//to be phased out, as it only allows for one hardcoded persistance backend
__attribute__ ((format (printf, 2, 3))) void *
RedisSendCommandOld (Session *sesn_ptr_this, const char *format, ...)
{
	PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);

	va_list ap;
	void *_reply = NULL;

	va_start(ap,format);
	_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
	va_end(ap);

	if (!_reply) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr_this, sesn_ptr_this?sesn_ptr_this->session_id:0,
				((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
		  struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP}; //give redis some breathing space and avoid resource  unavailable error msg
      nanosleep(&req, NULL);

			va_start(ap, format);
			_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
			va_end(ap);

			if (IS_PRESENT(_reply))	return _reply;
		}

		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERRO: ('%d'): EXITING: RE-ATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr_this, sesn_ptr_this?sesn_ptr_this->session_id:0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		exit(2);
		//return NULL;
	}

	return _reply;

}

__attribute__ ((format (printf, 2, 3))) void *
RedisSendCommand (CacheBackend *pers_ptr_in, const char *format, ...)
{
  CacheBackend *pers_ptr = NULL;
  if (IS_PRESENT(pers_ptr_in) && IS_PRESENT(pers_ptr_in->persistance_agent))	pers_ptr = pers_ptr_in;

  va_list ap;
  void *_reply = NULL;

  va_start(ap,format);
  _reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
  va_end(ap);

  if (!_reply) {
    syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...",  __func__, pthread_self(), &ufsrv_thread_context, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

    if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
      struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP}; //give redis some breathing space and avoid resource  unavailable error msg
      nanosleep(&req, NULL);

      va_start(ap, format);
      _reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
      va_end(ap);

      if (IS_PRESENT(_reply))	return _reply;
    }

    syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR ('%d'): EXITING: REATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

    exit(2);
    //		return NULL;
  }

  return_success:
  return _reply;

}

__attribute__ ((format (printf, 3, 4))) void *
RedisSendSessionCommand(Session *sesn_ptr_this, CacheBackend *pers_ptr_in, const char *format, ...)
{
	CacheBackend *pers_ptr = NULL;
	if (IS_PRESENT(pers_ptr_in) && IS_PRESENT(pers_ptr_in->persistance_agent))	pers_ptr = pers_ptr_in;

	va_list ap;
	void *_reply = NULL;

	va_start(ap,format);
	_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
	va_end(ap);

	if (!_reply) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr_this, sesn_ptr_this?sesn_ptr_this->session_id:0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
      struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP}; //give redis some breathing space and avoid resource  unavailable error msg
      nanosleep(&req, NULL);

			va_start(ap, format);
			_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
			va_end(ap);

			if (IS_PRESENT(_reply))	return _reply;
		}

		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): EXITING: REATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr_this, sesn_ptr_this?sesn_ptr_this->session_id:0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		exit(2);
		//		return NULL;
	}

	return_success:
	return _reply;

}

void *
RedisSendCommandWithCollection (Session *sesn_ptr, CacheBackend *pers_ptr, CollectionDescriptorPair *collection_argv_argvlen)
{
	void *_reply = NULL;

	_reply = redisCommandArgv((redisContext *)pers_ptr->persistance_agent, collection_argv_argvlen->first.collection_sz,
													 (const char **)collection_argv_argvlen->first.collection, (const size_t *)collection_argv_argvlen->second.collection);

	if (!_reply) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr), ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
      //give redis some breathing space and avoid resourec unavailable msg
      struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP};
      nanosleep(&req, NULL);

			_reply = redisCommandArgv((redisContext *)pers_ptr->persistance_agent, collection_argv_argvlen->first.collection_sz,
																 (const char **)collection_argv_argvlen->first.collection, (const size_t *)collection_argv_argvlen->second.collection);

			if (IS_PRESENT(_reply))	return _reply;
		}

		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): EXITING: REATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr), ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		exit(2);
//		return NULL;
	}

  return_success:
	return _reply;

}

__attribute__ ((format (printf, 2, 3))) void *
RedisSendCommandSessionless (void *ptr, const char *format, ...)
{
	PersistanceBackend *pers_ptr = (PersistanceBackend *)ptr;

	va_list ap;
	void *_reply = NULL;

	va_start(ap, format);
	_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
	va_end(ap);

	if (!_reply) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection", __func__, pthread_self(), &ufsrv_thread_context, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
      struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP}; //give redis some breathing space and avoid resource  unavailable error msg
      nanosleep(&req, NULL);

			va_start(ap, format);
			_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
			va_end(ap);

			if (IS_PRESENT(_reply))	return _reply;
		}

		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR ('%d'): EXITING: REATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		exit(2);
//		return NULL;
	}

	return _reply;

}

//tobe phased out
__attribute__ ((format (printf, 2, 3))) void *
RedisSendCommandMultiOld (Session *sesn_ptr, const char *format, ...)
{
	PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);

  va_list ap;

  va_start(ap, format);
  int reply = redisvAppendCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
  va_end(ap);

  if (reply != REDIS_OK) {

    syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, sesn_ptr?SESSION_ID(sesn_ptr):0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

    return NULL;
  }

	return_success:
	return (void *)1;

}

__attribute__ ((format (printf, 3, 4))) void *
RedisSendCommandMulti (Session *sesn_ptr, CacheBackend *pers_ptr, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	int reply = redisvAppendCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
	va_end(ap);


	if (reply!=REDIS_OK) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, SESSION_ID(sesn_ptr), ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		return NULL;
	}

	return_success:
	return (void *)1;

}

#include <sds.h>
/**
 *
 *  @brief: Used with multi send command. Resets connection with redis in case of connection error.
 */
int
RedisGetReply (Session *sesn_ptr, CacheBackend *pers_ptr, redisReply	**reply)
{
	int ret;
	sds obuf_redis_orig = sdsnewlen(((redisContext *)pers_ptr->persistance_agent)->obuf, sdslen(((redisContext *)pers_ptr->persistance_agent)->obuf));

	if ((ret=redisGetReply((redisContext *)pers_ptr->persistance_agent, (void *)reply)) != REDIS_OK) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, IS_PRESENT(sesn_ptr)?SESSION_ID(sesn_ptr):0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr)))) {
      struct timespec req = {.tv_sec = 0, .tv_nsec = _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP}; //give redis some breathing space and avoid resourec unavailable msg
      nanosleep(&req, NULL);

			((redisContext *)pers_ptr->persistance_agent)->obuf = obuf_redis_orig;
			ret = redisGetReply((redisContext *)pers_ptr->persistance_agent, (void *)reply);

			if (ret == REDIS_OK)	goto return_success;//this free obuf_redis_orig
		}

		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: ERROR ('%d'): EXITING: REATTEMPTED: REDIS COMMAND ERROR '%s'",  __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr, IS_PRESENT(sesn_ptr)?SESSION_ID(sesn_ptr):0,
						((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);
		sdsfree(obuf_redis_orig);

		exit(2);
		//return ret;
	}

	sdsfree(obuf_redis_orig);

	return_success:

	return ret;
}

unsigned
DisconnectRedisBackend(Session *sesn_ptr, int keep_fd)
{
	PersistanceBackend *pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);

  /* Free the context as well, but keep the fd if requested. */
  if (keep_fd)	return redisFreeKeepFd(pers_ptr->persistance_agent);

  redisFree(pers_ptr->persistance_agent);

  return 1;

}

void
PrintPersistanceError (Session *sesn_ptr, char *user_str)
{
	if (sesn_ptr) {

		syslog(LOG_INFO, "%s: ERROR ('%d'): REDIS COMMAND ERROR '%s'", user_str,  ((redisContext *)(sesn_ptr->persistance_backend->persistance_agent))->err, ((redisContext *)(sesn_ptr->persistance_backend->persistance_agent))->errstr);

	}
}

int
CheckForScript (RedisBackend *pers_ptr, const char *unique_id)
{
	//verify scripts
	//script exists 3a94e53b4b39b8229102c70d92a4ac3f6f8e3c1f

	redisReply *redis_ptr=(*pers_ptr->send_command)	(pers_ptr, "SCRIPT EXISTS %s", unique_id);

	if (!redis_ptr) {
		syslog(LOG_ERR, "%s: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE FOR SCRIPT VERIFICATION (NULL): EXITING...", __func__);
		 _exit (-1);
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
		 syslog(LOG_ERR, "%s: REDIS_REPLY_ERROR: COULD NOT GET REDIS RESPONSE FOR SCRIPT VERIFICATION: ERROR :' %s': EXITING...", __func__, redis_ptr->str);
		 _exit (-1);
	}

	if (redis_ptr->type == REDIS_REPLY_NIL) {
		 syslog(LOG_ERR, "%s: REDIS_REPLY_NIL COULD NOT GET REDIS RESPONSE FOR SCRIPT VERIFICATION: EXITING...", __func__);
		 _exit (-1);
	}

	if ((redis_ptr->type == REDIS_REPLY_ARRAY)&&(redis_ptr->element[0]->integer==1)) {
		syslog(LOG_INFO, "%s: SUCCESS: VERIFIED CRITICAL UNIQUE ID GENERATION SYSTEM...", __func__);
		freeReplyObject(redis_ptr);
	} else {
		syslog(LOG_ERR, "%s: CRITICAL ERROR: COULD NOT VERIFY CRITICAL LUA UNIQUE ID GENERATION FEATURE SCRIPT: EXITING...", __func__);
		return-1;
	}

	return 0;//success
}


#if 0
		  // The purpose of this is to get a 64-bit ID of the following
		  // format:
		  //
		  //  ABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCDDDDDDDDDDDD
		  //
		  // Where:
		  //   * A is the reserved signed bit .
		  //   * B is the timestamp in milliseconds since custom epoch bits, 41 in total.
		  //   * C is the logical shard ID, 10 bits in total.
		  //   * D is the sequence, 12 bits in total.
#endif
/**
 *   based on http://engineering.intenthq.com/2015/03/icicle-distributed-id-generation-with-redis-lua/
 *   To generate SHA1:
 *   /usr/local/redis/3.2.5/redis-cli -p 19705  SCRIPT LOAD "$(cat /opt/redis/redis_id_generation.lua)"
 */
unsigned long
GenerateCacheBackendId (PersistanceBackend *backend_ptr)
{
	unsigned long id = 0;

	#define LOGICAL_SHARD_ID_BITS 10
	#define SEQUENCE_BITS 12

	#define TIMESTAMP_SHIFT  (SEQUENCE_BITS + LOGICAL_SHARD_ID_BITS)
	#define LOGICAL_SHARD_ID_SHIFT  SEQUENCE_BITS

	// These three bitopped constants are also used as bit masks for the maximum value of the data they represent.
	#define MAX_SEQUENCE  ()~(-1 << SEQUENCE_BITS))//4095
	#define MAX_LOGICAL_SHARD_ID  (~(-1 << LOGICAL_SHARD_ID_BITS))//1023
	#define MIN_LOGICAL_SHARD_ID  1

	#define CUSTOM_EPOCH_IN_MILLIS  1401277473000UL//Wed, 28 May 2014 11:44:33 GMT
	#define MILLIS_IN_ONE_MICRO_SEC	1000UL
	#define MICROS_IN_ONE_SEC 1000000UL

	#define MAX_BATCH_SIZE  (MAX_SEQUENCE + 1)

	 ///opt/redis/redis-cli -p 19705 EVALSHA 21bee0f6116c759cc9fd0407658f4ec88cf0a60e 4 4095 1 1023 1 <---1 is batch size)
	redisReply *redis_ptr = (*backend_ptr->send_command_sessionless) (backend_ptr, "EVALSHA %s 4 %d %d %d %d", REDIS_SCRIPT_SHA1_UNIQUE_ID, 4095, 1, 1023, 1);//REDIS_SCRIPT_SHA1_UNIQUE_ID

	if 	(IS_EMPTY(redis_ptr))									  goto return_error_connection;
	if	(redis_ptr->type == REDIS_REPLY_ERROR)	goto return_error_reply;
	if 	(redis_ptr->type == REDIS_REPLY_NIL)		goto return_error_nil;

	//TODO: NOTICE: this should correspond with the fields returned by the lua script
	#define _REDIS_UID_FIELDS_COUNT	5
	if (redis_ptr->elements != _REDIS_UID_FIELDS_COUNT) goto return_error_incomplete_set;//emty set

	unsigned long sequence		=	redis_ptr->element[0]->integer;
	unsigned long timestamp		=	((redis_ptr->element[3]->integer*MICROS_IN_ONE_SEC) + redis_ptr->element[4]->integer)/MILLIS_IN_ONE_MICRO_SEC;
	unsigned shard_id 				= redis_ptr->element[2]->integer;

	id = ((timestamp - CUSTOM_EPOCH_IN_MILLIS) << TIMESTAMP_SHIFT)|
				(shard_id << LOGICAL_SHARD_ID_SHIFT)|
				sequence;

	goto return_deallocate;

	return_error_reply:
	syslog(LOG_DEBUG, "%s (pid:%lu', th_ctx:'%p', error:'%s'}: ERROR: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE", __func__, pthread_self(), &ufsrv_thread_context, redis_ptr->str);
	goto	return_deallocate;

	return_error_nil:
	syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', error:'%s'}: ERROR: NIL REPLY.",  __func__, pthread_self(), &ufsrv_thread_context, redis_ptr->str);
	goto return_deallocate;

	return_error_incomplete_set:
	syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: COULD NOT RETRIEVE RECORD: received empty, or incomplete set: '%lu'", __func__, pthread_self(), &ufsrv_thread_context, redis_ptr->elements);
	goto return_deallocate;

	return_deallocate:
	freeReplyObject(redis_ptr);
	goto return_result;

#ifdef __UF_FULLDEBUG
		  syslog(LOG_DEBUG, LOGSTR_SESSION_DISTRIBUTED_ID_GENERATED, __func__, GET_BITS_IN_BETWEEN(id, 22, 63), GET_BITS_IN_BETWEEN(id, 12, 22), GET_N_BITS_FROM_REAR(id, 12), id, LOGCODE_SESSION_DISTRIBUTED_ID_GENERATED);
#endif

	return_error_connection:
	syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', redis_err:'%d', redis_error:'%s'}: ERROR: CONNECTION ERROR", __func__, pthread_self(), &ufsrv_thread_context, ((redisContext *)(backend_ptr->persistance_agent))->err, ((redisContext *)(backend_ptr->persistance_agent))->errstr);
	goto return_result;

	return_result:
	return id;

}

/**
 * Generic redis connection function. Must be passed fully specified configuration details.
 * Designed to work with initialising redis backends
 * @return on success the initialised context or NULL
 */
static redisContext *
ConnectRedisBackend (const struct BackendConfig *config_ptr)
{
	redisContext *c = NULL;

	if (config_ptr->type == SOCK_TCP) {
		c = redisConnect(config_ptr->con_tcp.host, config_ptr->con_tcp.port);
	} else if (config_ptr->type == SOCK_UNIX) {
    c = redisConnectUnix(config_ptr->con_unix.path);
  } else if (config_ptr->type == SOCK_FD) {
#if 0
        /* Create a dummy connection just to get an fd to inherit */
        redisContext *dummy_ctx = redisConnectUnix(config.con_unix.path);
        if (dummy_ctx)
        {
            int fd = DisconnectPersistanceBackend(dummy_ctx, 1);
            //printf("Connecting to inherited fd %d\n", fd);
            c = redisConnectFd(fd);
        }
#endif
	}

	if (IS_EMPTY(c)) {
		syslog(LOG_INFO, "%s {pid:'%lu', TH_CTX'%p'}: Connection error: can't allocate redis context...", __func__, pthread_self(), &ufsrv_thread_context);
		return NULL;
	} else if (c->err) {
		goto return_context;
	} else {
		redisSetTimeout(c, config_ptr->con_tcp.timeout);
	}

	return_context:
	return c;

}/**/

/**
 * @param cfg the calling function must pass a fully initialised configuration parameters for the target backend
 * When passing in_per_ptr we assume we are reinitialisng an existing backend
 * free context and reallocate
 */
RedisBackend *InitialiseRedisBackend (RedisBackend *in_per_ptr, struct BackendConfig *cfg)
{
	redisReply 		*reply;
	RedisBackend 	*per_ptr					=	NULL;

	if (!in_per_ptr) {
		per_ptr = calloc(1, sizeof(RedisBackend));
	} else {
		per_ptr = in_per_ptr;

		if (per_ptr->persistance_agent) {
			redisFree(per_ptr->persistance_agent);//Because we are reinitialising an exiting backend connection
		}
	}

	per_ptr->persistance_agent = ConnectRedisBackend(cfg);
	if (!per_ptr->persistance_agent) {
		if (!in_per_ptr)	free (per_ptr);

		return NULL;
	}

	if (per_ptr->persistance_agent->err>0) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'} : ERROR: COULD NOT CONNECT TO REDIS BACKEND (%s:%d): '%s'", __func__, pthread_self(), &ufsrv_thread_context, cfg->con_tcp.host, cfg->con_tcp.port, ((redisContext *)per_ptr->persistance_agent)->errstr);

		redisFree(per_ptr->persistance_agent);

		if (!in_per_ptr)	free (per_ptr);

		return NULL;
	}

	//we are fully setup now: test connection with actual command
	reply = redisCommand(per_ptr->persistance_agent, "PING");
	if ((reply) && (reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str,"pong") == 0)) {
		extern ufsrv *const masterptr;

		freeReplyObject(reply);

		per_ptr->send_command             = cfg->cache_backend.send_command;
		per_ptr->send_command_multi       = cfg->cache_backend.send_command_multi;
		per_ptr->send_command_sessionless = cfg->cache_backend.send_command_sessionless;
		per_ptr->init_connection          = (RedisBackend *(*)(RedisBackend *))cfg->cache_backend.init_connection;

		syslog (LOG_INFO, "%s {pid:'%lu', th_ctx:'%p'}: Received PONG confirmation from RedisBackend (fd:%d, o:'%p', %s:%d): Issuing CLIENT SETNAME %s-%d-%lu...", __func__, pthread_self(), &ufsrv_thread_context, per_ptr->persistance_agent->fd, per_ptr,  cfg->con_tcp.host, cfg->con_tcp.port, masterptr->server_descriptive_name, cfg->con_tcp.port, pthread_self());

		reply = redisCommand(per_ptr->persistance_agent, "CLIENT SETNAME %s-%d-%lu", masterptr->server_descriptive_name, cfg->con_tcp.port, pthread_self());
		if (IS_PRESENT(reply) && (strcmp(reply->str, "OK")==0))	freeReplyObject(reply);
    else {
      syslog (LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR: COULD NOT SETNAME %s-%d-%lu following a PING", __func__, pthread_self(), &ufsrv_thread_context, masterptr->server_descriptive_name, cfg->con_tcp.port, pthread_self());

      redisFree(per_ptr->persistance_agent);

      if (!in_per_ptr)	free (per_ptr);

      return NULL;

    }
		return per_ptr;
	} else {
		syslog (LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR: DID NOT receive pong confirmation from RedisBackend (%s:%d)...", __func__, pthread_self(), &ufsrv_thread_context, cfg->con_tcp.host, cfg->con_tcp.port);

		redisFree(per_ptr->persistance_agent);

		if (!in_per_ptr)	free (per_ptr);

		return NULL;
	}

	return NULL;

}
