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

/*
**
** MODULEID("$Id: sredird.h,v 1.1 1999/09/01 00:42:00 ayman Exp $")
**
*/

#ifndef NPORTREDIRD_H
# define NPORTREDIRD_H

#include <sys/time.h>
#include <standard_net_includes.h>
#include <main_types.h>
#include <recycler/instance_type.h>
#include <ufsrvresult_type.h>
#include <uflib/adt/adt_linkedlist.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue_type.h>
#include <ufsrv_instance_descriptor_type.h>
#include <utils_curve.h>

#include <http_request_handler.h>

#include <sockets.h>
#include <session.h>

#include <pthread.h>
#include <uflib/db/db_sql.h>

#include <server_geogroups_enum.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <zkgroup.h>

enum {
  LOG_MODE_SYSLOG, LOG_MODE_OWN
 }; /*struct msredird.log_mode*/

 enum {
  RUNNING_MODE_DAEMON, RUNNING_MODE_TERM
 };

 enum {
  REDIRECTION_ACTIVE, REDIRECTION_DISABLED
 }; /*status*/

 enum {
	 DELEGTYPE_TIMER=0, DELEGTYPE_MSGQUEUE
 };

typedef enum ServerRunMode {
	RUNMODE_NORMAL, RUNMODE_SHADOW, RUNMODE_INVALID
} ServerRunMode;

#define IS_RUNMODE_VALID(x) (x<RUNMODE_INVALID && x>=RUNMODE_NORMAL)

#define PIPE_READ_END masterptr->pipefds[0]
#define PIPE_WRITE_END masterptr->pipefds[1]
#define WORK_DELEGATOR_PIPE masterptr->work_delegator_pipe
#define WORK_DELEGATOR_PIPE_SESSION SessionOffInstanceHolder(masterptr->work_delegator_pipe)
#define WORK_DELEGATOR_PIPE_WRITE_END(x) (x)->ssptr->sock //fd[1]
#define WORK_DELEGATOR_PIPE_READ_END(x) (x)->dsptr->sock	//fd[0]
#define MASTER_CONF_SERVER_PRIVATEKEY masterptr->ufsrv_crypto.private_key_server
#define MASTER_CONF_SERVER_PUBLICKEY masterptr->ufsrv_crypto.public_key_server
#define MASTER_CONF_SERVER_PUBLICKEY_SERIALISED masterptr->ufsrv_crypto.public_key_server_serialised
#define MASTER_CONF_SERVER_KEYID masterptr->ufsrv_crypto.server_keyid

#define MASTER_CONF_SERVER_PRIVATE_PARAMS masterptr->ufsrv_crypto.private_server_params
#define MASTER_CONF_SERVER_PUBLIC_PARAMS masterptr->ufsrv_crypto.public_server_params

//server_class_<geogroup>
#define REDIS_CMD_CONFIG_UFSRV_REQID_INC			"HINCRBY _CONFIG_UFSRV_%s_%d reqid 1"
#define REDIS_CMD_CONFIG_UFSRV_REQID_GET			"HMGET _CONFIG_UFSRV_%s_%d reqid"
#define REDIS_CMD_CONFIG_UFSRV_GROUPSZ_GET		"HMGET _CONFIG_UFSRV_%s_%d group_sz"
 //<server class> <%server geo group> <server id>
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_ADD			"SADD _CONFIG_UFSRV_MEMBERS_%s_%d %d"
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_GETALL	"SMEMBERS _CONFIG_UFSRV_MEMBERS_%s_%d" //<%class>_<%geogroup> : 'ufsrv_3'
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_REM			"SREM _CONFIG_UFSRV_MEMBERS_%s:%d %d"
#define REDIS_CMD_CONFIG_UFSRV_MEMBERS_SZ			"SCARD _CONFIG_UFSRV_MEMBERS_%s:%d"

 //individual attributes for a given server
 //<server class> <%server geo group> <server id> <last active time>
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTR_LAST_SET			"HMSET _CONFIG_UFSRV_MEMBER_%s_%d_%d last %lu"
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTR_LAST_GET			"HMGET _CONFIG_UFSRV_MEMBER_%s_%d_%d last"
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTRS_GETALL			"HGETALL _CONFIG_UFSRV_MEMBER_%s_%d_%d"
#define REDIS_CMD_CONFIG_UFSRV_MEMBER_ATTRS_IDENTIFIERS_SET		"HMSET _CONFIG_UFSRV_MEMBER_%s_%d_%d pid %i ip %s started %lu serverid %i last %lu"

 typedef struct ufsrv {
			time_t when;  /* up-time... */
			struct timeval ufsrv_time;
			int				ufsrv_geogroup;
			ServerRunMode	server_run_mode;
			unsigned 	running_mode; /*enum*/
			unsigned 	log_mode; //own|syslog enum
			unsigned 	ssl_support; //boolean in configfile
			char 			config_dir[MBUF];
			char 			config_file[MBUF];
			char 			server_class[MINIBUF];
			char 			intra_ufsrv_classname[MINIBUF];	//calls name of the server that handled intra commands
			char 			*server_descriptive_name;
      pid_t serverpid;
			int serverid;
			int serverid_by_user;
			int server_cpu_affinity;
			int listen_on_port;
			char main_listener_address[MBUF];
			unsigned main_listener_protoid; //TODO: this is temporary hack until true concurrent protocol support is added
			int command_console_port;
			char command_console_address[MBUF];
			char ufsrvmsgqueue_address[MBUF];
			int ufsrvmsgqueue_port;
			char persistance_backend_address[MBUF];
			int persistance_backend_port;
			char cache_backend_address_usrmsg[MBUF];
			int cache_backend_port_usrmsg;
			char cache_backend_address_fence[MBUF];
			int cache_backend_port_fence;
      char ufsrvmedia_upload_uri[SBUF];
			size_t buffer_size;//how much toallocate  for incming buffer
			size_t buffer_maxsize;//upper limit on dynamically adjusted buffer_size;
			struct {
				int port;
				char address[SBUF];
				char password[SBUF];
				char username[SBUF];
			} db_backend;
			struct {
				int port;
				char address[SBUF];
			} stats_backend;
			struct {
							int port;
							char address[SBUF];
			} geoip_backend;
			struct {
				int		allocation_groups;
				size_t	allocation_group_sz;
				double 	allocation_trigger_threshold;
			}	memspecs_session;

			struct {
				SSL_CTX *ssl_ctx;//for console
				SSL_CTX *ssl_user_ctx; //normal client
				SSL *ssl_console;//each user session will have one of these
				pthread_mutex_t *ssl_mutexes;//array of mutexes used for SSL locking
				unsigned initialised;
				size_t          server_keyid; //facilitate future revocation of invalid server keys that might be in circulation
				ec_private_key 	private_key_server;
				ec_public_key		public_key_server;
				ec_public_key		public_key_server_serialised;
				//credentials issuance
				uint8_t  private_server_params[SERVER_SECRET_PARAMS_LEN];
        uint8_t  public_server_params[SERVER_PUBLIC_PARAMS_LEN];

			}	ufsrv_crypto;

			int pipefds[2]; //pipe between main thread and WorkDelegatorThread read fd[0], write fd[1]
			InstanceHolderForSession *work_delegator_pipe;

			//these are used by the main thread, separate instances from session workers and ufsr workers
			MessageQueueBackend 		*msgqueue_sub;//backend connection representing MessageQueue subscriber listener. Global one per uf server instance.
			PersistanceBackend 			*persistance_backend;//redis connection for the main thread; ie non worker or delegator
			UserMessageCacheBackend *usrmsg_cachebackend;
			FenceCacheBackend				*fence_cachebackend;
			InstrumentationBackend 	*instrumentation_backend;
			UFSRVResult             result;
			//not in use yet
			//struct _h_connection 		*db_backend; //db connection for the main thread; non worker or delegator

			struct sockaddr_in instrumentation_backend_server;//statsd udp connection

		  lua_State *lua_ptr;//not thread-safe

		  //Session worker threads specific keys for various backend access objects.
		  //Each thread uses the same key to store and retrieve its own instance of the backend object.
		  //actual backend references are defined in session_type.h
		  //TODO: move into  SessionDelegator struct
		  ////makesure you initialise all keys in UFSRVThreadsOnceInitialiser (void);
		  struct {
			  pthread_once_t ufsrv_once; //once only initialser for the threading subsystem for this server
			  pthread_key_t ufsrv_thread_context_key;
			  pthread_key_t ufsrv_http_request_context_key;//persistance
			  pthread_key_t ufsrv_data_key;//redis cachebackend
			  pthread_key_t	ufsrv_usrmsg_key; //redis cachbackend
			  pthread_key_t	ufsrv_fence_key; //redis cachbackend
			  pthread_key_t ufsrv_msgqueue_pub_key;//ufsrv msgqueue pub redis connection
			  pthread_key_t ufsrv_instrumentation_backend_key;
			  pthread_key_t ufsrv_db_backend_key;//key to multiplex db backend connections
		  } threads_subsystem;

 } ufsrv;

// typedef struct UfsrvInstanceDescriptor {
//	 int 				serverid;
//	 int 				serverid_by_user;
//	 int				ufsrv_geogroup;
//	 const char 			*server_class;
//	 const char 			*server_descriptive_name;
//	 unsigned long reqid;	//bit of a bolt on, should probably go somewhere else, but it relates to the context of a request served by instance
// } UfsrvInstanceDescriptor;

#define _CONF_UFSRV_GEOGROUP(x)	(x)->ufsrv_geogroup
#define _CONF_READ_BLOCKSZ(x)	x->buffer_size
#define _CONF_READ_MAXBLOCKSZ(x)	x->buffer_maxsize
#define _CONF_SERVER_RUNMODE(x)	(x)->server_run_mode
#define _CONF_SESNMEMSPECS_ALLOC_GROUPS(x)	x->memspecs_session.allocation_groups
#define _CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(x)	x->memspecs_session.allocation_group_sz
#define _CONF_SESNMEMSPECS_ALLOC_THRESHOLD(x)	x->memspecs_session.allocation_trigger_threshold

 typedef int (*CallbackWorkExecutor)(MessageContextData *);
 typedef MessageContextData * (*CallbackWorkArgExtractor)(MessageQueueMsgPayload *);

 typedef struct WorkerJobSpecs{
	unsigned delegator_type;
	void *args;
	int (*work_exec)(MessageContextData *);
	MessageContextData * (*fetch_work_arg)(MessageQueueMsgPayload *);
 } WorkerJobSpecs;

void InitUFSRV (void);
void InitHTTPClient(void);
void InitSSL (void);
void UfsrvMainListener (Socket *sock_ptr_listener, Socket *sock_ptr_console);
void InvokeMainListener (int protocol_id, Socket *sock_ptr_listener, ClientContextData *context_ptr);
int AnswerTelnetRequest (Socket *);
Socket *InitMainListener (int protocol_id);
void InitWorkersDelegator (int protocol_id);
long long UfsrvConfigGetReqid (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup);
bool UfsrvConfigRegisterUfsrverInstance (PersistanceBackend	*pers_ptr);
UfsrvInstanceDescriptor *GetUfsrvInstance (Session *sesn_ptr, const char *server_class, unsigned geogroup, UfsrvInstanceDescriptor *instance_ptr_out);
bool UfsrvConfigRegisterUfsrverActivity (PersistanceBackend	*pers_ptr, time_t activity_time);
bool UfsrvConfigRegisterUfsrverActivityWithSession (Session *sesn_ptr, time_t activity_time);
CollectionDescriptor *UfsrvConfigGetGeoGroup (Session *sesn_ptr, const char *server_class, unsigned ufsrv_geogroup, CollectionDescriptor *collection_ptr_ids, CollectionDescriptor *collection_ptr_times);
size_t UfsrvConfigGetGeogroupSize (Session *sesn_ptr);
time_t UfsrvConfigGetUfsrverActivityTime (Session *sesn_ptr, const char *server_class, int ufsrv_geogroup, int serverid_by_user);

int UfsrvGetServerId();

#endif

