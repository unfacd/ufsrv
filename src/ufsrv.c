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
#include <error.h>
#include <misc.h>
#include <recycler/recycler.h>
#include <uflib/adt/adt_lamport_queue.h>
#include <uflib/adt/adt_queue.h>
#include <session.h>
#include <net.h>
#include <ufsrv_core/protocol/protocol.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <sessions_delegator_type.h>
#include <nportredird.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <uflib/db/db_sql.h>
#include <include/nportredird.h>

static ufsrv master;
ufsrv *const masterptr = &master;

#ifdef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
static QueueClientData *listener_connection_queue[_CONFIG_LISTENER_CONNECTION_QUEUE_SZ];
#endif
//otherwise use traditional Queue with dynamic allocation

extern const Protocol 		*const protocols_registry_ptr;
extern SessionsDelegator 	*const sessions_delegator_ptr;

static void InitNewConnectionsQueue(void);
static void InitConnectionListenerToWorkDelegatorPipe(void);
static void UFSRVThreadsOnceInitialiser(void);
static void _InitServerCertificates();
static void _InitCredentialsIssuanceServerParams();

static inline void InitHashTables(void);

//This is the classic self-pipe-trick
//backdoor into the WorkDelegatorThread to unblock it from epoll_wait call to process new incoming connection
//unidirectial pipe source is writer end in main listening thread fd[1]
//reader end is destination socket in WorkDelegatorThread fd[0]
//flow source:fd[1] -> destination:fd[0]
 static void
 InitConnectionListenerToWorkDelegatorPipe (void)
 {
 	Socket *ss_ptr, *ds_ptr = NULL;
 	Session	*sesn_ptr = NULL;

 	if ((pipe2(masterptr->pipefds, O_NONBLOCK)) == -1) {
 		syslog(LOG_ERR, "%s: COULD NOT initialise Pipe(errno:%d): exiting...", __func__, errno);
 		exit (-1);
 	}

 	ss_ptr = malloc((sizeof(Socket)));//writer end in main main listening  thread
 	memset (ss_ptr, 0, sizeof(Socket));

 	ss_ptr->type = SOCK_PIPEWRITER;
	ss_ptr->sock = PIPE_WRITE_END;
	strcpy (ss_ptr->address, "pipe.writer.localhost");
	strcpy (ss_ptr->haddress, "pipe.reader.localhost");

	ds_ptr = malloc(sizeof(Socket));//reader end in WorkDelegator thread
	memset (ds_ptr, 0, sizeof(Socket));
	ds_ptr->type = SOCK_PIPEREADER;
	ds_ptr->sock = PIPE_READ_END;
	strcpy (ds_ptr->address, "pipe.reader.localhost");
	strcpy (ds_ptr->haddress, "pipe.writer.localhost");

	if (!(sesn_ptr = InstantiateSession(ss_ptr, ds_ptr, 0, -1))) {
	  close (ss_ptr->sock);
	  close (ds_ptr->sock);
	  free (ss_ptr);
	  free (ds_ptr);

	  syslog(LOG_ERR, "%s: COULD NOT initialise Pipe Interconnection Session: exiting...", __func__);
	  _exit (-1);
 }

	//handy access. Even though not managed out off recycler, for consistency we envelope with InstanceHolder
	InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
	SetInstance(instance_sesn_ptr, sesn_ptr);
	WORK_DELEGATOR_PIPE = instance_sesn_ptr;

	syslog(LOG_INFO, "%s: successfully initialised Pipe Interconnection Session (cid:'%lu') conection: WRITER: '%s:%d' READER: '%s:%d'",__func__,
			sesn_ptr->session_id, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

 }

/**
* 	@brief: This SPSC queue is shared between AnswerTelnetRequest (producer) and ThreadWorkerDelegator (consumer).
* 	Ensure instrumentation is already initialised in order to correctly report on queue capacity.
*/
static void
InitNewConnectionsQueue (void)
{
#ifdef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE
	syslog(LOG_INFO, ">> %s: New Connections Queue: Initialising lockless queue...", __func__);
	LamportQueueInit(&(sessions_delegator_ptr->new_connections.queue), listener_connection_queue, _CONFIG_LISTENER_CONNECTION_QUEUE_SZ);

	statsd_gauge(masterptr->instrumentation_backend, "listener.connection.queue_capacity", _CONFIG_LISTENER_CONNECTION_QUEUE_SZ);
#else
	syslog(LOG_INFO, ">> %s: New Connections Queue: Initialising locking...", __func__);

	pthread_mutexattr_init(&(sessions_delegator_ptr->new_connections.queue_mutex_attr));//&new_connections_queue_mutex_attr);
	pthread_mutexattr_settype(&(sessions_delegator_ptr->new_connections.queue_mutex_attr), PTHREAD_MUTEX_ERRORCHECK);

	pthread_mutex_init (&(sessions_delegator_ptr->new_connections.queue_mutex),
			&(sessions_delegator_ptr->new_connections.queue_mutex_attr));
#endif
}

//>>>>>>>>>> SSL thread locking semantics callbacks
static unsigned long thread_id_function();
static unsigned long thread_id_function(void)
{
	return ((unsigned long) pthread_self());

}

static void locking_function(int mode, int id, const char *file, int line);
static void locking_function(int mode, int id, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	pthread_mutex_lock(&masterptr->ufsrv_crypto.ssl_mutexes[id]);
	else
	pthread_mutex_unlock(&masterptr->ufsrv_crypto.ssl_mutexes[id]);

}

//dynamic
struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
};

static struct CRYPTO_dynlock_value *dyn_create_func(const char *file, int line);
static struct CRYPTO_dynlock_value *
dyn_create_func(const char *file, int line)
{
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value *) malloc(sizeof(struct CRYPTO_dynlock_value));
	pthread_mutex_init(&value->mutex, NULL);
	return value;
}

static void
dyn_destroy_func(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	pthread_mutex_destroy(&l->mutex);
	free(l);

}

static void dyn_lock_func(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line);
static void dyn_lock_func(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if(mode & CRYPTO_LOCK)
	pthread_mutex_lock(&l->mutex);
	else
	pthread_mutex_unlock(&l->mutex);

}

//>>>>>>>>>>>>>>>>>>>>>>>> end of SSL thread locking semantics callbacks


//http://www.informit.com/authors/bio/1933efae-b8cc-4f72-aebd-a4b7c7f761c2
//http://www.cse.cuhk.edu.hk/~pclee/tsinghua/files/lec3.pdf
void
InitSSL (void)
{
	if (masterptr->ufsrv_crypto.initialised==0)
	{
		const SSL_METHOD *ssl_method_console, *ssl_method_client;

		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		ssl_method_console=TLSv1_server_method();
		if((masterptr->ufsrv_crypto.ssl_ctx= SSL_CTX_new(ssl_method_console))==NULL)
		{
			syslog (LOG_INFO, "%s: ERROR: COULD NOT INITIALISE SSL CTX for CONSOLE connections...", __func__);
			exit(-1);
		}

		if((masterptr->ufsrv_crypto.ssl_console= SSL_new(masterptr->ufsrv_crypto.ssl_ctx))==NULL)
		{
			syslog (LOG_INFO, "%s: ERROR: COULD NOT OBTAIN SSL object for CONSOLE CTX...", __func__);
			exit(-1);
		}

		ssl_method_client=TLSv1_server_method();
		if((masterptr->ufsrv_crypto.ssl_user_ctx= SSL_CTX_new(ssl_method_client))==NULL)
		{
			syslog (LOG_INFO, "%s: ERROR: COULD NOT INITIALISE SSL CTX for CLIENT connections...", __func__);
			exit(-1);
		}



		{//console certificate
			lua_getglobal(LUA_CTX, "ufsrv_ssl");
			if (!lua_istable(LUA_CTX, -1))
			{
				  //error(masterptr->lua_ptr, "`ufsrv_ssl' is not a valid config table");
				  error(-1, 0, "`ufsrv_ssl' is not a valid config table");
			}

			char *l=LUA_GetFieldToString("location");
			char *c=LUA_GetFieldToString("certificate");
			char *k=LUA_GetFieldToString("key");
			syslog (LOG_DEBUG, "%s: ufsrv_ssl location='%s' key='%s' certificate='%s'...",  __func__, l, k, c);

			char *file_path;
			asprintf(&file_path, "%s/%s", masterptr->config_dir, c); free(c);
			SSL_CTX_use_certificate_file(masterptr->ufsrv_crypto.ssl_ctx, file_path, SSL_FILETYPE_PEM); free(file_path);

			asprintf(&file_path, "%s/%s", masterptr->config_dir, k); free(k);
			SSL_CTX_use_PrivateKey_file(masterptr->ufsrv_crypto.ssl_ctx, file_path, SSL_FILETYPE_PEM); free(file_path);
			free(l);

			if(!(SSL_CTX_check_private_key(masterptr->ufsrv_crypto.ssl_ctx)))
			{
				syslog (LOG_INFO, "%s: ERROR: COULD NOT CHECK PRIVATE KEY FOR CONSOLE CTX...", __func__);
				exit (-1);
			}
		}

		{//client certificate
			lua_getglobal(LUA_CTX, "ufsrv_user_ssl");
			if (!lua_istable(LUA_CTX, -1))
			{
				  error(-1, 0, "`ufsrv_user_ssl' is not a valid config table");
			}
			char *l=LUA_GetFieldToString("location");
			char *c=LUA_GetFieldToString("certificate");
			char *k=LUA_GetFieldToString("key");
			syslog (LOG_DEBUG, "%s: ufsrv_user_ssl location='%s' key='%s' certificate='%s'...",  __func__, l, k, c);

			char *file_path;
			asprintf(&file_path, "%s/%s", masterptr->config_dir, c); free(c);
			SSL_CTX_use_certificate_file(masterptr->ufsrv_crypto.ssl_user_ctx, file_path, SSL_FILETYPE_PEM); free(file_path);

			asprintf(&file_path, "%s/%s", masterptr->config_dir, k); free(k);
			SSL_CTX_use_PrivateKey_file(masterptr->ufsrv_crypto.ssl_user_ctx, file_path, SSL_FILETYPE_PEM); free(file_path);
			free(l);

			if(!(SSL_CTX_check_private_key(masterptr->ufsrv_crypto.ssl_user_ctx)))
			{
				syslog (LOG_INFO, "%s: ERROR: COULD NOT CHECK PRIVATE KEY FOR USER CTX...", __func__);
				exit (-1);
			}

		}


		{//static allocation of SSL threading semantics
			int i;
			masterptr->ufsrv_crypto.ssl_mutexes = (pthread_mutex_t *) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
			for(i=0; i<CRYPTO_num_locks(); i++)
			{
				pthread_mutex_init(&masterptr->ufsrv_crypto.ssl_mutexes[i], NULL);
			}

			//static calbacks
			CRYPTO_set_id_callback(thread_id_function);
			CRYPTO_set_locking_callback(locking_function);

			//dynamic callbacks
			CRYPTO_set_dynlock_create_callback(dyn_create_func);
			CRYPTO_set_dynlock_lock_callback(dyn_lock_func);
			CRYPTO_set_dynlock_destroy_callback(dyn_destroy_func);
		}

		masterptr->ufsrv_crypto.initialised=1;

		syslog (LOG_INFO, "%s: SUCCESS: SSL subsystem initialised.", __func__);

	}
	else
	{
		syslog (LOG_INFO, "%s: SSL subsystem is already initialised", __func__);
	}

}

static void _InitServerCertificates ()
{
	int size_out;
	unsigned char *key_raw;

	//todo: these should be defined out of config file. Private key can be fed via command line
	key_raw = base64_decode((const unsigned char *)SERVER_PRIVATEKEY, strlen(SERVER_PRIVATEKEY), &size_out);
  memcpy(MASTER_CONF_SERVER_PRIVATEKEY.data,  key_raw, size_out);
  memset(key_raw, '\0', size_out);
  free(key_raw);

	key_raw = base64_decode((const unsigned char *)SERVER_PUBLICKEY, strlen(SERVER_PUBLICKEY), &size_out);
  memcpy(MASTER_CONF_SERVER_PUBLICKEY.data, key_raw, size_out);
	free(key_raw);

	key_raw = base64_decode((const unsigned char *)SERVER_PUBLICKEY_SERIALISED, strlen(SERVER_PUBLICKEY_SERIALISED), &size_out);
  memcpy(MASTER_CONF_SERVER_PUBLICKEY_SERIALISED.data, key_raw, size_out);
  free(key_raw);

  MASTER_CONF_SERVER_KEYID       = SERVER_KEYID;
}

static void _InitCredentialsIssuanceServerParams()
{
  int size_out = 0;

  base64_decode_buffered((const unsigned char *)PRIVATE_SERVER_PARAM, strlen(PRIVATE_SERVER_PARAM), MASTER_CONF_SERVER_PRIVATE_PARAMS, &size_out);
  if (size_out != SERVER_SECRET_PARAMS_LEN) {
    syslog(LOG_ERR, "%s: ERROR (size: '%d', param:'%s'): COULD NOT DECODE PRIVATE SERVER PARAMS: TERMINATING...", __func__, size_out, PRIVATE_SERVER_PARAM);

    exit(-1);
  }

  size_out = 0;
  base64_decode_buffered((const unsigned char *)PUBLIC_SERVER_PARAM, strlen(PUBLIC_SERVER_PARAM), MASTER_CONF_SERVER_PUBLIC_PARAMS, &size_out);
  if (size_out != SERVER_PUBLIC_PARAMS_LEN) {
    syslog(LOG_ERR, "%s: ERROR (size: '%d', param:'%s'): COULD NOT DECODE PUBLIC SERVER PARAMS: TERMINATING...", __func__, size_out, PUBLIC_SERVER_PARAM);

    exit(-1);
  }


}

void InvokeMainListener (int protocol_id, Socket *sock_ptr_listener, ClientContextData *context_ptr)
{
	if (_PROTOCOL_CLLBACKS_MAIN_LISTENER(protocols_registry_ptr, protocol_id)) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_MAIN_LISTENER_INVOKE(protocols_registry_ptr, protocol_id, sock_ptr_listener, context_ptr);
	}
}

/**
 * 	@brief: Generic listening semantics for delegated connection requests
 */
#include <command_console_thread.h>

void
UfsrvMainListener (Socket *sock_ptr_listener, Socket *sock_ptr_console)
{
	int 		x;
	fd_set 	fd,
					xfd;

	sd_notifyf(0, "READY=1\n"
							 "STATUS=Main Listener ready...\n");
	again:
	dummy ();
	FD_ZERO(&fd);
	FD_ZERO(&xfd);

	if (IS_PRESENT(sock_ptr_listener))	FD_SET(sock_ptr_listener->sock, &fd);
	if (unlikely(IS_PRESENT(sock_ptr_console)))		FD_SET(sock_ptr_console->sock, &fd);

	while (1 != 2) {
		x = select (FD_SETSIZE, &fd, NULL, NULL, NULL);

		if (x > 0) {
			if (FD_ISSET(sock_ptr_listener->sock, &fd)) {
				AnswerTelnetRequest (sock_ptr_listener);
			}

			if (IS_PRESENT(sock_ptr_console)) {
				if (FD_ISSET(sock_ptr_console->sock, &fd)) {
					syslog(LOG_INFO, "Main: Processing an incoming connection for Command Console on socket %d.", sock_ptr_console->sock);

					AnswerCommandConsoleRequest (sock_ptr_console);
				}
			}

		}
		else if (x == 0) {
		  /* timeout */
		} else if (x == -1 && errno != EINTR) {
			syslog(LOG_ERR, "%s {pid:'%lu', errno:'%d'}: !!ERROR!! Select error in main thread: EXITING", __func__, pthread_self(), errno);
			close (sock_ptr_listener->sock);
			if (IS_PRESENT(sock_ptr_console))	close (sock_ptr_console->sock);

			_exit (-2);
		}

		goto again;

	}

}

void
InitHTTPClient (void)
{
	syslog(LOG_INFO, "Initialisaing HTTPClient subsystem...");

	curl_global_init(CURL_GLOBAL_ALL);
}

static void
UFSRVThreadsOnceInitialiser (void)
{
	syslog(LOG_INFO, "%s: Performing pthread ONCE initialisation...", __func__);

	//initialise thread specific key for session io worker threads
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_thread_context_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_http_request_context_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_data_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_usrmsg_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_fence_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(masterptr->threads_subsystem.ufsrv_db_backend_key), NULL);//TODO: no clean up callback

	pthread_key_create (&(sessions_delegator_ptr->worker_delegator_pipe_key), NULL);//TODO: no clean up callback


	//initialise thread specific key for ufsrv worker threads as defined in SessionDelegator
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_thread_context_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_http_request_context_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.worker_persistance_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.worker_usrmsg_cachebackend_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.worker_fence_cachebackend_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), NULL);//TODO: no clean up callback
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_msgqueue_pub_key), NULL);
	pthread_key_create (&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_db_backend_key), NULL);

}

void
InitUFSRV (void)
{
	masterptr->threads_subsystem.ufsrv_once=PTHREAD_ONCE_INIT;
	pthread_once(&(masterptr->threads_subsystem.ufsrv_once), UFSRVThreadsOnceInitialiser);

	_InitServerCertificates();
	_InitCredentialsIssuanceServerParams();
	InitSSL();

	InstrumentationBackendServerInit (masterptr->stats_backend.address, masterptr->stats_backend.port);

	masterptr->instrumentation_backend = InstrumentationBackendInit (NULL);
	if (IS_PRESENT(masterptr->instrumentation_backend))	syslog(LOG_DEBUG, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Main Thread: '%lu'...", __func__, masterptr->instrumentation_backend, pthread_self());
	else	syslog(LOG_DEBUG, "%s: ERROR: COULD NOT Initialise Instrumentation Backend for Main Thread: '%lu'...", __func__, pthread_self());


	{
    PersistanceBackend *per_ptr = InitialisePersistanceBackend(NULL);
		if (per_ptr) {
			masterptr->persistance_backend = per_ptr;
      syslog(LOG_INFO, "%s: SUCCESS {o:'%p'}: Initialised Persistence Backend for Main Listener thread...", __func__, per_ptr);
		} else {
			syslog(LOG_INFO, "%s: ERROR: COULD NOT INITIALISE Persistence Backend for Main Listener thread: Exiting", __func__);
			_exit (-1);
		}

    UserMessageCacheBackend *per_ptr_usrmsg = InitialiseCacheBackendUserMessage(NULL);
    if (IS_PRESENT(per_ptr_usrmsg)) {
      masterptr->usrmsg_cachebackend = per_ptr_usrmsg;
      syslog(LOG_INFO, "%s: SUCCESS {o:'%p'}: Initialised Cache Backend UserMessage for Main Listener thread...", __func__, per_ptr_usrmsg);
    } else {
      syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend UserMessage  for Main Listener  thread: Exiting...", __func__);
      _exit (-1);
    }

		{
			//verify scripts. check redis.h for details
			//script exists 3a94e53b4b39b8229102c70d92a4ac3f6f8e3c1f

			redisReply *redis_ptr = (*masterptr->persistance_backend->send_command_sessionless)(masterptr->persistance_backend, "SCRIPT EXISTS %s", REDIS_SCRIPT_SHA1_UNIQUE_ID);

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
			if ((redis_ptr->type == REDIS_REPLY_ARRAY) && (redis_ptr->element[0]->integer == 1)) {
				syslog(LOG_INFO, "%s: SUCCESS: VERIFIED CRITICAL UNIQUE ID GENERATION SYSTEM...", __func__);
				freeReplyObject(redis_ptr);
			} else {
				syslog(LOG_ERR, "%s: CRITICAL ERROR: COULD NOT VERIFY CRITICAL LUA UNIQUE ID GENERATION FEATURE SCRIPT: EXITING...", __func__);
				_exit (-1);
			}
		}
	}

	InitMysql ();

	InitConnectionListenerToWorkDelegatorPipe();

	InitNewConnectionsQueue ();

	InitHashTables ();

	InitSessionRecyclerTypePool ();

	if (UfsrvConfigRegisterUfsrverInstance(masterptr->persistance_backend)) {
		syslog(LOG_INFO, "%s: SUCCESS: Registered with Configuration Server", __func__);
#if 0
		Session sesn={0};
		int ufsrv_group[10]={0};
		sesn.persistance_backend=masterptr->persistance_backend;
		sesn.geogroup=3;
		UfsrvConfigGetGeoGroup (&sesn, &((CollectionDescriptor){(collection_t **)ufsrv_group, 0}));
#endif
	} else {
		syslog(LOG_ERR, "%s: CRITICAL ERROR: COULD NOT REGISTER WITH CONFIGURATION SERVER: EXITING...", __func__);
		_exit (-1);
	}

 }  /**/

/**
 *  executed in a ufsrv thread context, so issuing mysql lib call unsigned long mysql_thread_id(MYSQL *mysql) returns
 *  client thread associated with this ufsrv thread. or "SELECT CONNECTION_ID();"
 */
struct _h_connection *InitialiseDbBackend (void)
{
  struct _h_connection *db_ptr;

//ANNOTATE_IGNORE_READS_BEGIN();
  //__vdrd_AnnotateIgnoreReadsBegin();
  db_ptr = h_connect_mariadb(masterptr->db_backend.address, masterptr->db_backend.username, masterptr->db_backend.password, CONFIG_DBBACKEND_DBNAME, masterptr->db_backend.port, NULL);
//ANNOTATE_IGNORE_READS_END();
  //__vdrd_AnnotateIgnoreReadsEnd();
  if (db_ptr) {
    SqlServerDisplayConnectedUsers (db_ptr);
  }

  return db_ptr;

}

#define COPY_SOCKET_CONNECTED_ADDRESSES \
				sesn_ptr->ssptr->sock = nsocket;\
				strcpy (sesn_ptr->ssptr->haddress, (char *)inet_ntoa(hisaddr.sin_addr));\
				strcpy (sesn_ptr->ssptr->address, masterptr->main_listener_address);\
				sesn_ptr->ssptr->hport = ntohs(hisaddr.sin_port);\
				sesn_ptr->ssptr->port = masterptr->listen_on_port;


#define LOCK_NEW_CONNECTIONS_QUEUE \
		if ((lock_status = pthread_mutex_lock (&(sessions_delegator_ptr->new_connections.queue_mutex)))) {\
			syslog(LOG_WARNING, "%s: COULD NOT LOCK on connection_queue_mutex (errno=%d)", __func__, errno);\
		}

#define UNLOCK_NEW_CONNECTIONS_QUEUE \
		if ((lock_status = pthread_mutex_unlock (&(sessions_delegator_ptr->new_connections.queue_mutex)))) {\
			syslog(LOG_WARNING, "AnswerTelnetRequest: COULD NOT UNLOCK on connection_queue_mutex (errno=%d)", errno);\
		}


static inline void
InitHashTables ()
{// Hashtables
	SessionsDelegator *const sd_ptr = sessions_delegator_ptr;

	if (HashTableLockingInstantiate(&(sd_ptr->hashed_sessions.hashtable), (offsetof(Session, session_id)), sizeof(unsigned long), HASH_ITEM_NOT_PTR_TYPE, "SessionsHashTable", (ItemExtractor)GetClientContextData)) {
		syslog(LOG_INFO, "%s: SUCCESS: Sessions HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, sd_ptr->hashed_sessions.hashtable.fKeyOffset, sd_ptr->hashed_sessions.hashtable.fKeySize);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE Sessions HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}

	//this is a char array, not pointer
	if (HashTableLockingInstantiate(&(sd_ptr->hashed_cookies.hashtable), (offsetof(Session, session_cookie)), KEY_SIZE_ZERO, HASH_ITEM_NOT_PTR_TYPE, "CookiesHashTable", (ItemExtractor)GetClientContextData)) {
		syslog(LOG_INFO, "%s: SUCCESS: SessionCookies HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, sd_ptr->hashed_cookies.hashtable.fKeyOffset, sd_ptr->hashed_cookies.hashtable.fKeySize);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE SessionCookies HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}

	if (HashTableLockingInstantiate(&(sd_ptr->hashed_userids.hashtable), (offsetof(Session, sservice.user.user_details.user_id)), sizeof(unsigned long), HASH_ITEM_NOT_PTR_TYPE, "UserIdHashTable", (ItemExtractor)GetClientContextData)) {
		syslog(LOG_INFO, "%s: SUCCESS: UserIds HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, sd_ptr->hashed_userids.hashtable.fKeyOffset, sd_ptr->hashed_userids.hashtable.fKeySize);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE UserIds HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}

	if (HashTableLockingInstantiate(&(sd_ptr->hashed_usernames.hashtable), (offsetof(Session, sservice.user.user_details.user_name)), KEY_SIZE_ZERO, HASH_ITEM_IS_PTR_TYPE, "UsernamesHashtable", (ItemExtractor)GetClientContextData)) {
		syslog(LOG_INFO, "%s: SUCCESS: SessionCookies HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, sd_ptr->hashed_usernames.hashtable.fKeyOffset, sd_ptr->hashed_usernames.hashtable.fKeySize);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE Usernames HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}

}

static bool _IsRateLimitExceededForNewConnection (struct sockaddr_in *addr);

#ifdef CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE

int
AnswerTelnetRequest (Socket *s_ptr_listening)
{
	int	nsocket,
			sin_size;
	Session *sesn_ptr;
	struct sockaddr_in hisaddr;

	sin_size = sizeof(struct sockaddr_in);

	nsocket = accept(s_ptr_listening->sock, (struct sockaddr *)&hisaddr, (socklen_t *)&sin_size);
	int this_errno = errno;

	if ((nsocket < 0) && (this_errno != EWOULDBLOCK)) {
		syslog (LOG_ERR, LOGSTR_MAINLISTENER_ACCEPT_ERROR,  __func__, masterptr->listen_on_port, this_errno, strerror(this_errno), LOGCODE_MAINLISTENER_ACCEPT_ERROR);

		return 0;
	}

#if 0 //currently relying on loadbalancer for this
	if (_IsRateLimitExceededForNewConnection(&hisaddr)) {
	  close(nsocket);
	  return 0;
	}
#endif

  int opt = 1;
  setsockopt (nsocket, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(int));

  SetSocketFlags (nsocket, 1, O_NONBLOCK);

   //up-to this point we have a fully connected socket

	InstanceHolderForSession *instance_sesn_ptr = (InstanceHolderForSession *)RecyclerGet(1, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);
	if (IS_EMPTY(instance_sesn_ptr)) {
		close (nsocket);
		return 0;
	}

  sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	COPY_SOCKET_CONNECTED_ADDRESSES

  sesn_ptr->stat |= SESNSTATUS_CONNECTED;

	if (!LamportQueuePush(&(sessions_delegator_ptr->new_connections.queue), (QueueClientData *)instance_sesn_ptr)) {
	 syslog (LOG_DEBUG, "%s (cid:'%lu', o:'%p', fd'%d', queue_sz:'%lu'): ERROR: COULD NOT ENQUEUE NEW CONNECTION: DROPPING...",   __func__, SESSION_ID(sesn_ptr), sesn_ptr, sesn_ptr->ssptr->sock, LamportQueueLeasedSize(&(sessions_delegator_ptr->new_connections.queue)));
	 goto return_error;
	}

  sesn_ptr->when_serviced_start = time(NULL);//corresponding endtime recorded  in ThreadWorkerDelegator()

	statsd_gauge_dec(masterptr->instrumentation_backend, "listener.connection.queue_capacity", 1);

#ifdef __UF_FULLDEBUG
	syslog (LOG_DEBUG, LOGSTR_MAINLISTENER_ACCEPT_QUEUED,  __func__, SESSION_ID(sesnptr), sesnptr, SESSION_SOCKETFD(sesnptr), QUEUE_ENTRIES_COUNT(new_connections_queue_ptr), LOGCODE_MAINLISTENER_ACCEPT_QUEUED);
#endif

  #define PIPE_GO_MSG "G"
  const char *marshal_msg = PIPE_GO_MSG;
  ssize_t actual_written_size = 0;

  ///syslog (LOG_INFO, "AnswerTelnetRequest: ATTEMPTING to write to 'New Connections Pipe'...");
  Session *sesn_ptr_pipe = WORK_DELEGATOR_PIPE_SESSION;
  while (actual_written_size < (sizeof(PIPE_GO_MSG) - 1)) {
    ssize_t written = write(WORK_DELEGATOR_PIPE_WRITE_END(sesn_ptr_pipe), marshal_msg + actual_written_size, (sizeof(PIPE_GO_MSG) - 1) - actual_written_size);
    if (written < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        //TODO: we don't really care so long as it is not pipe error connections will just pile up and eventually delegator wil pick it up...
        syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_BLOCKING,  __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_BLOCKING);
        goto return_error;
      }

      syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_ERROR, __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_ERROR);
      goto return_error;
    }

    //nonerror
    actual_written_size += written;
  }//write loop

#ifdef __UF_FULLDEBUG
  if (actual_written_size==(sizeof(PIPE_GO_MSG)-1)) syslog(LOG_DEBUG, "%s: SUCCESSFULLY written to 'New Connections Pipe': cid='%lu'",   __func__, SESSION_ID(sesnptr));
#endif

   return nsocket;

   return_error:
   close (nsocket);
   SessionReturnToRecycler(instance_sesn_ptr, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);

   return 0;

 }

#else

int AnswerTelnetRequest (Socket *s_ptr_listening)
 
{
	int 		socket_fd_new;
	//sin_size;
	Session *sesnptr;
	//struct sockaddr_in hisaddr;

	//IP6/IP agnostic
	struct sockaddr_storage address_peer;
	socklen_t               address_len_peer = sizeof(address_peer);

#if 0
	//or alternatively using NetworkSocketAddress
	NetworkSocketAddress socket_address_peer;
	InitNetworkSocketAddress (&socket_address_peer, AF_UNSPEC);
	socket_fd_new=accept(s_ptr_listening->sock, &socket_address_peer.u.sa, &socket_address_peer.len);
#endif

	sin_size=sizeof(struct sockaddr_in);

	//socket_fd_new=accept(s_ptr_listening->sock, (struct sockaddr *)&hisaddr, (socklen_t *)&sin_size);
	socket_fd_new=accept(s_ptr_listening->sock, (struct sockaddr *)&address_peer, (socklen_t *)&address_len_peer);
	int this_errno=errno;

	if ((socket_fd_new<0)&&(this_errno!=EWOULDBLOCK))
	{
		syslog (LOG_ERR, LOGSTR_MAINLISTENER_ACCEPT_ERROR,  __func__, masterptr->listen_on_port, this_errno, strerror(this_errno), LOGCODE_MAINLISTENER_ACCEPT_ERROR);

		return 0;
	}

	//CHECK_IF_MAX_CONNECTION_REACHED;

	//if ((RedirecionConnectionValid(rptr, &hisaddr, &nsocket)), nsocket==0)	return 0;

	//set upper limit on read without this client may block connections.
	//http://stackoverflow.com/questions/4181784/how-to-set-socket-timeout-in-c-when-making-multiple-connections
	{
		int opt=1;
#if 0
		struct timeval t;
		t.tv_sec = 5000 / 1000;//5 seconds timeut
		t.tv_usec = ( 5000 % 1000 ) * 1000;

		setsockopt(nsocket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(struct timeval));
#endif
		setsockopt (socket_fd_new, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(int));

		SetSocketFlags (socket_fd_new, 1, O_NONBLOCK);
	}

   //up-to this point we have a fully connected socket

	sesnptr=(Session *)RecyclerGet(1, NULL, CALL_FLAG_HASH_SESSION_LOCALLY);
	if (!sesnptr)
	{
		close (socket_fd_new);
		return 0;
	}


   COPY_SOCKET_CONNECTED_ADDRESSES;

   sesnptr->stat|=SESNSTATUS_CONNECTED;

   Queue *new_connections_queue_ptr=&(sessions_delegator_ptr->new_connections.queue);
   QueueEntry *qe_ptr=NULL;

   	//lock synch writing to the queue between listener and delegator. Pipe write is used to signalqueue read read request
   ///syslog (LOG_DEBUG, "%s (cid='%lu' o='%p' fd='%d'): Adding new connection to 'New Connections Queue' acquiring mutex lock...",   __func__, SESSION_ID(sesnptr), sesnptr, sesnptr->ssptr->sock);

    int lock_status;
   	LOCK_NEW_CONNECTIONS_QUEUE;
	qe_ptr=AddQueue(new_connections_queue_ptr);
	qe_ptr->whatever=(void *)sesnptr;
	sesnptr->when_serviced_start=time(NULL);

	statsd_gauge(masterptr->instrumentation_backend, "listener.connection.queue_size", new_connections_queue_ptr->nEntries);

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, LOGSTR_MAINLISTENER_ACCEPT_QUEUED,  __func__, SESSION_ID(sesnptr), sesnptr, SESSION_SOCKETFD(sesnptr), QUEUE_ENTRIES_COUNT(new_connections_queue_ptr), LOGCODE_MAINLISTENER_ACCEPT_QUEUED);
#endif

	UNLOCK_NEW_CONNECTIONS_QUEUE;
	//unlock

	{//pipe write code-block
		const char *marshal_msg="GO";
		const ssize_t required_write_size=strlen(marshal_msg);
		ssize_t actual_written_size=0;
    Session *sesn_ptr_pipe = WORK_DELEGATOR_PIPE_SESSION;
		while (actual_written_size<required_write_size)
		{
			ssize_t written=write(WORK_DELEGATOR_PIPE_WRITE_END(sesn_ptr_pipe), marshal_msg+actual_written_size, required_write_size-actual_written_size);//fd[1]
			if (written<0)
			{
				if (errno==EAGAIN || errno==EWOULDBLOCK)
				{
					//TODO: we don't really care so long as it is not pipe error connections will just pile up and eventually delegator wil pick it up...
					syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_BLOCKING,  __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_BLOCKING);
					//sleep (1);
					//continue;
					return 1;
				}

				//pipe error
				syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_ERROR, __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_ERROR);
				return 0;
				//TODO: recovery
			}

			//nonerror
			actual_written_size += written;

		}//write loop

#ifdef __UF_FULLDEBUG
		if (actual_written_size==required_write_size) syslog(LOG_DEBUG, "%s: SUCCESSFULLY written to 'New Connections Pipe': cid='%lu'",   __func__, SESSION_ID(sesnptr));
#endif

	}//pipe write code-block

   return socket_fd_new;

 }  /**/

#endif	//_CONFIG_LISTENER_CONNECTION_QUEUE_SZ

#include <ufsrv_core/ratelimit/ratelimit.h>
__unused static bool
_IsRateLimitExceededForNewConnection (struct sockaddr_in *addr)
{
  char ipstr[INET6_ADDRSTRLEN];
  __unused int port;

  if (((struct sockaddr_storage *)addr)->ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)addr;
//    port = ntohs(s->sin_port);
    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
  } else {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
//    port = ntohs(s->sin6_port);
    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
  }

  return IsRateLimitExceededForIPAddress(masterptr->usrmsg_cachebackend, ipstr, RLNS_CONNECTONS, &(masterptr->result));
}

//
//main processing port
//
Socket *
InitMainListener (int protocol_id)
{
	if (_PROTOCOL_CLLBACKS_LISTENER_INIT(protocols_registry_ptr, protocol_id)) {
		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_LISTENER_INIT_INVOKE(protocols_registry_ptr, protocol_id);
		if (_RESULT_TYPE_SUCCESS(res_ptr))	return (Socket *)_RESULT_USERDATA(res_ptr);
	}

	return NULL;

}

void
InitWorkersDelegator (int protocol_id)
{
	if (_PROTOCOL_CLLBACKS_WORKERS_DELEGATOR_INIT(protocols_registry_ptr, protocol_id))
	{
		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_WORKERS_DELEGATOR_INIT_INVOKE(protocols_registry_ptr, protocol_id);
		//if (_RESULT_TYPE_SUCCESS(res_ptr))	return (Socket *)_RESULT_USERDATA(res_ptr);
	}

	return;

}//eo

static UFSRVResult *_CacheBackendUfsrvConfigRegisterUfsrverInstance (PersistanceBackend	*pers_ptr, UFSRVResult *res_ptr);
static UFSRVResult * _CacheBackendSetUfsrvConfigReqid (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup);
static UFSRVResult *_CacheBackendUfsrvConfigRegisterUfsrverActivity (PersistanceBackend	*pers_ptr, time_t activity_time, UFSRVResult *res_ptr);
static UFSRVResult *_CacheBackendUfsrvConfigRegisterUfsrverActivityWithSession (Session *sesn_ptr, time_t activity_time);
static UFSRVResult *_CacheBackendUfsrvConfigGetGeoGroup (Session *sesn_ptr, const char *server_class, unsigned, CollectionDescriptor *, CollectionDescriptor *);
static UFSRVResult *_CacheBackendUfsrvConfigGetGeogroupSize (Session *sesn_ptr);
static UFSRVResult *_CacheBackendUfsrvConfigGetUfsrverActivityTime (Session *sesn_ptr, const char *server_class, int geo_group, int);

/**
 * 	@brief: given a geogroup get a server instance to be used for request serving. server_class is the calls of
 * 	servers responsible for serving. ufsrvap --> ufsrv
 */
UfsrvInstanceDescriptor *
GetUfsrvInstance (Session *sesn_ptr, const char *server_class, unsigned ufsrv_geogroup, UfsrvInstanceDescriptor *instance_ptr_out)
{
	int 									collection_idxs[CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP]				=	{0};
	time_t								collection_idxs_times[CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP]	=	{0};
	CollectionDescriptor 	collection_ufsrv_ids																					=	{.collection=(collection_t **)collection_idxs, CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP};
	CollectionDescriptor 	collection_ufsrv_times																				=	{.collection=(collection_t **)collection_idxs_times, CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP};

	if (unlikely((ufsrv_geogroup == 0)))	ufsrv_geogroup = _CONFIGDEFAULT_DEFAULT_UFSRVGEOGROUP;

	UfsrvConfigGetGeoGroup (sesn_ptr, server_class, ufsrv_geogroup, &collection_ufsrv_ids, &collection_ufsrv_times);

	if (collection_ufsrv_ids.collection_sz > 0) {
		size_t		counter		=	0;
		time_t		last_activity_time,
							time_now	=	time(NULL);
		long long reqid			=	UfsrvConfigGetReqid (sesn_ptr, server_class, ufsrv_geogroup);

		if (reqid > 0) {
			int ufsrv_instance									=	reqid % collection_ufsrv_ids.collection_sz;
			int ufsrv_instance_idx							=	ufsrv_instance < CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP?ufsrv_instance:CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP-1;

			do {
				last_activity_time = UfsrvConfigGetUfsrverActivityTime (sesn_ptr, server_class, ufsrv_geogroup, collection_idxs[ufsrv_instance_idx]);
				if (time_now - last_activity_time < _CONFIGDEDAULT_IDLE_TIME_INTERVAL_INTRA_REQUEST) {
					instance_ptr_out->serverid_by_user	=	collection_idxs[ufsrv_instance_idx];
					instance_ptr_out->reqid							=	reqid;
					instance_ptr_out->ufsrv_geogroup		=	ufsrv_geogroup;
					instance_ptr_out->server_class			=	server_class;//TODO: this constant per instance and references invariant global value

	#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', reqid:'%llu', counter:'%lu', idx:'%d', server_id:'%d'}: Retrieved Ufsrv Instance...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), reqid, counter, ufsrv_instance_idx, collection_idxs[ufsrv_instance_idx]);
	#endif

					return (instance_ptr_out);
				} else {
					ufsrv_instance_idx = (ufsrv_instance_idx + 1) % collection_ufsrv_ids.collection_sz;//wrap around as necessary
					syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', reqid:'%llu, counter:'%lu',  server_id:'%d', ufsrv_instance_idx_incremented:'%d', time_now:'%lu', last_activity_time:'%lu', time_diff:'%lu'}: WARNING: FOUND UNRESPONSIVE SERVER IN GEOGROUP: TRYING NEXT", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), reqid, counter, collection_idxs[ufsrv_instance_idx], ufsrv_instance_idx, time_now, last_activity_time, time_now-last_activity_time);
				}
			} while (++counter <= collection_ufsrv_ids.collection_sz);
		} else {
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', reqid:'%llu'}: ERROR: COULD NOT UNLOCK RETRIEVE REQUEST ID", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), reqid);
		}
	}

	return NULL;
}

bool
UfsrvConfigRegisterUfsrverInstance (PersistanceBackend	*pers_ptr)
{
	UFSRVResult 	res={0};
	_CacheBackendUfsrvConfigRegisterUfsrverInstance (pers_ptr, &res);
	 if (res.result_type==RESULT_TYPE_SUCCESS)	return  true;

	 return false;
}

 /**
  * 	@brief Register presence with the Configuration Server. The registration gequires the server to specify its geo_group, which
  * 	is a configuration file setting.
  * 	@WARNING: This doesn't have Session linked to it so must use send_command_sessionless
  */
 static UFSRVResult *
_CacheBackendUfsrvConfigRegisterUfsrverInstance (PersistanceBackend	*pers_ptr, UFSRVResult *res_ptr)
{
	int rescode;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command_sessionless)(pers_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTRS_IDENTIFIERS_SET, masterptr->server_class, masterptr->ufsrv_geogroup, masterptr->serverid_by_user, getpid(), "0.0.0.0", masterptr->when, masterptr->serverid, masterptr->when)))	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_STATUS && !(strcasecmp (redis_ptr->str, "OK") == 0)) {
		syslog(LOG_ERR, "%s {pid:'%lu, reply:'%s'}: ERROR: COULD NOT SET SERVER ATTRIBUTES...", __func__, pthread_self(), redis_ptr->str);
		rescode = RESCODE_BACKEND_DATA;
		goto return_error;
	}

	freeReplyObject(redis_ptr);

	if (!(redis_ptr = (*pers_ptr->send_command_sessionless)(pers_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_ADD, masterptr->server_class, masterptr->ufsrv_geogroup, masterptr->serverid_by_user)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {// && redis_ptr->integer==1) //it can still suceed with 0 if the element is already in the set
		long long result = redis_ptr->integer;
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_RES(res_ptr, (void *) (uintptr_t)result, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: wrapper routine
 */
long long
UfsrvConfigGetReqid (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup)
{
 _CacheBackendSetUfsrvConfigReqid (sesn_ptr, server_class, ufsrv_geogroup);
 if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	return  (long long)(intptr_t)SESSION_RESULT_USERDATA(sesn_ptr);

 return 0;
}

/**
 * 	@brief: Increment and return the request counter
 */
 static UFSRVResult *
 _CacheBackendSetUfsrvConfigReqid (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup)
 {
 	int rescode;

 	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
 	redisReply 					*redis_ptr	=	NULL;

 	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_REQID_INC, server_class, ufsrv_geogroup)))	goto return_redis_error;

 	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
 		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t)redis_ptr->integer, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
 	}

 	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
 	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

 	return_redis_error:
 	if (IS_EMPTY(redis_ptr)) {
 	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
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

 time_t
UfsrvConfigGetUfsrverActivityTime (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup, int serverid_by_user)
{
	_CacheBackendUfsrvConfigGetUfsrverActivityTime (sesn_ptr, server_class, ufsrv_geogroup, serverid_by_user);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return ((time_t)(intptr_t)SESSION_RESULT_USERDATA(sesn_ptr));
	}

	return 0;
}

 static UFSRVResult *
_CacheBackendUfsrvConfigGetUfsrverActivityTime (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup, int serverid_by_user)
{
	int rescode;

	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTR_LAST_GET, server_class, ufsrv_geogroup, serverid_by_user)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_ARRAY) {// && redis_ptr->integer==1) //it can still succeed with 0 if the element is already in the set
		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t)strtoul(redis_ptr->element[0]->str, NULL, 10), RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

 /**
  * 	@brief wrapper function
  */
 bool
 UfsrvConfigRegisterUfsrverActivityWithSession (Session *sesn_ptr, time_t activity_time)
 {
 	_CacheBackendUfsrvConfigRegisterUfsrverActivityWithSession (sesn_ptr, activity_time);
 	 if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	return  true;

 	 return false;
 }

 static UFSRVResult *
 _CacheBackendUfsrvConfigRegisterUfsrverActivityWithSession (Session *sesn_ptr, time_t activity_time)
 {
 	int rescode;

 	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
 	redisReply 					*redis_ptr	=	NULL;

 	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTR_LAST_SET, masterptr->server_class, masterptr->ufsrv_geogroup, masterptr->serverid_by_user, activity_time)))	goto return_redis_error;

 	if (redis_ptr->type == REDIS_REPLY_INTEGER) {// && redis_ptr->integer==1) //it can still suceed with 0 if the element is already in the set
 		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t)redis_ptr->integer, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
 	}

 	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
 	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

 	return_redis_error:
 	if (IS_EMPTY(redis_ptr)) {
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
 	}
 	if (redis_ptr->type == REDIS_REPLY_ERROR) {
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
 	 rescode = RESCODE_BACKEND_DATA; goto return_error;
 	}
 	if (redis_ptr->type == REDIS_REPLY_NIL) {
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
 	 rescode = RESCODE_BACKEND_DATA; goto return_error;
 	}

 	return_error:
 	freeReplyObject(redis_ptr);
 	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

 }

bool
UfsrvConfigRegisterUfsrverActivity (PersistanceBackend	*pers_ptr, time_t activity_time)
{
	UFSRVResult 	res = {0};
	_CacheBackendUfsrvConfigRegisterUfsrverActivity (pers_ptr, activity_time, &res);
	 if (res.result_type == RESULT_TYPE_SUCCESS)	return  true;

	 return false;
}

 /**
  * 	@brief Register presence with the Configuration Server. The registration requires the server to specify its geo_group, which
  * 	is a configuration file setting.
  * 	@returns: RESULT_TYPE_SUCCESS
  * 	@WARNING: This doesn't have Session linked to it so must use send_command_sessionless
  */
 static UFSRVResult *
_CacheBackendUfsrvConfigRegisterUfsrverActivity (PersistanceBackend	*pers_ptr, time_t activity_time, UFSRVResult *res_ptr)
{
	int rescode;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command_sessionless)(pers_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTR_LAST_SET, masterptr->server_class, masterptr->ufsrv_geogroup, masterptr->serverid_by_user, activity_time)))	goto redis_connectivity_error;

	if ((redis_ptr->type == REDIS_REPLY_STATUS) && (strcasecmp(redis_ptr->str,"OK") == 0)) {
		//NOTE: redis_ptr->integer is not relevant for HMSET
		_RETURN_RESULT_RES(res_ptr, (void *) (uintptr_t)redis_ptr->integer, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto redis_error_reply;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto redis_error_nil;

	redis_connectivity_error:
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
   goto return_error;

	redis_error_reply:
	syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
	rescode = RESCODE_BACKEND_DATA; goto return_error_free;

	redis_error_nil:
  syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
	rescode = RESCODE_BACKEND_DATA; goto return_error_free;

	return_error_free:
	freeReplyObject(redis_ptr);

	return_error:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

 /**
 * 	@brief: Wrapper routine to get server collection serving a geogroup with which session is affiliated and served by.
 * 	@param collection_ptr: must be be fully allocated by user
 * 	@returns: collection of server id (integers)
 */
 CollectionDescriptor *
 UfsrvConfigGetGeoGroup (Session *sesn_ptr, const char *server_class, unsigned ufsrv_geogroup, CollectionDescriptor *collection_ptr_ids, CollectionDescriptor *collection_ptr_times)
 {
	 _CacheBackendUfsrvConfigGetGeoGroup (sesn_ptr, server_class, ufsrv_geogroup, collection_ptr_ids, collection_ptr_times);

	 if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	return  (CollectionDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);

	 return NULL;
 }

 /**
  * 	@brief: returns  id/last service times pairs for member servers of a given geogroup.
  * 	We allow for reassignment of user's geogroup to a default one if: 1)user's was set to zero, 2)user's group returned zero server collection
  *
  */
static UFSRVResult *
_CacheBackendUfsrvConfigGetGeoGroup (Session *sesn_ptr, const char *server_class, unsigned ufsrv_geogroup, CollectionDescriptor *collection_ptr_ids, CollectionDescriptor *collection_ptr_times_DEL)
{
	bool default_group_flagged=false;
	int rescode;

	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	run_command:

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_GETALL, server_class, ufsrv_geogroup)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_ARRAY && redis_ptr->elements>0)
	{
		int 		*ufsrv_group_ids				=	(int *)collection_ptr_ids->collection;
		//time_t	*ufsrv_group_times	=	(time_t *)collection_ptr_times->collection;

		for (size_t i=0; i<redis_ptr->elements; i++)
		{
			ufsrv_group_ids[i]=atoi(redis_ptr->element[i]->str);
		}

		collection_ptr_ids->collection_sz=redis_ptr->elements;
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, collection_ptr_ids, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}
	else
	{
		//group is empty (eg servers all died, or that group dosnt have assigned servers), reassign to known default group
		if (unlikely(default_group_flagged))	goto return_default_group_flagged;

		ufsrv_geogroup=_CONFIGDEFAULT_DEFAULT_UFSRVGEOGROUP;
		default_group_flagged=true;//to avoid endless loop in case the default grous has also died
		goto run_command;
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_default_group_flagged:
	syslog(LOG_ERR, "%s {pid:'%lu, o:'%p', ufsrv_geogroup_user:'%d', ufsrv_geogroup_default:'%d'}: DEFAULT GEO GROUP WAS FLAGGED UNAVAILABLE",  __func__, pthread_self(), sesn_ptr, SESSION_UFSRV_GEOGROUP(sesn_ptr), ufsrv_geogroup);
	rescode=RESCODE_UFSRVGEOGROUP_DEFAULT;
	collection_ptr_ids->collection_sz=0;

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

 /**
  * 	@brief: returns the identifier portion only for servers withing a given geogroup
  */
 /**
  * 	@brief: Get server collection serving a geogroup with which session is affiliated and served by.
  * 	@param collection_ptr: must be be fully allocated by user
  * 	@returns: collection of server id (integers)
  */
 __unused static UFSRVResult *
 _CacheBackendUfsrvConfigGetGeoGroupInstances (Session *sesn_ptr, CollectionDescriptor *collection_ptr)
 {
 	int rescode;

 	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
 	redisReply 					*redis_ptr	=	NULL;

 	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBER_GETALL, masterptr->server_class, SESSION_UFSRV_GEOGROUP(sesn_ptr))))	goto return_redis_error;

 	if (redis_ptr->type==REDIS_REPLY_ARRAY && redis_ptr->elements>0)
 	{
 		int *ufsrv_group=(int *)collection_ptr->collection;
 		for (size_t i=0; i<redis_ptr->elements; i++)
		{
 			char *last_service_time;
 			if ((last_service_time=strchr(redis_ptr->element[0]->str, ':')))	{*last_service_time++='\0';}
 			ufsrv_group[i]=atoi(redis_ptr->element[i]->str);
		}
 		collection_ptr->collection_sz=redis_ptr->elements;
 		freeReplyObject(redis_ptr);
 		_RETURN_RESULT_SESN(sesn_ptr, collection_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
 	}

 	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
 	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

 	return_redis_error:
 	if (IS_EMPTY(redis_ptr))
 	{
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
 	}
 	if (redis_ptr->type==REDIS_REPLY_ERROR)
 	{
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
 	 rescode=RESCODE_BACKEND_DATA; goto return_error;
 	}
 	if (redis_ptr->type==REDIS_REPLY_NIL)
 	{
 	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
 	 rescode=RESCODE_BACKEND_DATA; goto return_error;
 	}

 	return_error:
 	freeReplyObject(redis_ptr);
 	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

 }
 //

 /**
  * 	@brief: Wrapper routine to get the number of present servers within a give geogroup
  */
 size_t
 UfsrvConfigGetGeogroupSize (Session *sesn_ptr)
 {
	 _CacheBackendUfsrvConfigGetGeogroupSize (sesn_ptr);
	 if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	return  (size_t)(intptr_t)SESSION_RESULT_USERDATA(sesn_ptr);

	 return 0;
 }

 /**
  * 	@brief: return the number of servers present in a given geogroup area
  */
 static UFSRVResult *
_CacheBackendUfsrvConfigGetGeogroupSize (Session *sesn_ptr)
{
	int rescode;

	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_CONFIG_UFSRV_MEMBERS_SZ, masterptr->server_class, SESSION_UFSRV_GEOGROUP(sesn_ptr))))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER)// && redis_ptr->integer==1) //it can still suceed with 0 if the element is already in the set
	{
		long long group_sz=redis_ptr->integer;
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t)group_sz, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self());
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu}: ERROR: NIL SET",  __func__, pthread_self());
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

__attribute_const__ int UfsrvGetServerId()
{
  return masterptr->serverid;
}
