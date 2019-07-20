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

#ifndef SRC_INCLUDE_SESSION_TYPE_H_
#define SRC_INCLUDE_SESSION_TYPE_H_

#include <instance_type.h>
#include <queue.h>
#include <socket_type.h>
#include <persistance_type.h>
#include <db_sql.h>
#include <instrumentation_backend.h>
#include <ufsrvmsgqueue_type.h>
#include <session_service_type.h>
#include <share_list_type.h>
#include <server_geogroups_enum.h>
#include <thread_context_type.h>

//various session status flags
#define SESNSTATUS_SET(x,y)						((x)|=y)
#define SESNSTATUS_UNSET(x,y)					((x)&=~y)
#define SESNSTATUS_IS_SET(x,y)				((x)&y)

#define SESNSTATUS_HANDSHAKED					(0x1UL<<1UL)
#define SESNSTATUS_AUTHENTICATED			(0x1UL<<2UL)
#define SESNSTATUS_CONNECTED					(0x1UL<<3UL)//mutually exclusive with SUSEND both cannot be on at the same time
#define SESNSTATUS_SUSPENDED	 			  (0x1UL<<4UL)//previously connected|authenticated|handshaked... fully suspended
#define SESNSTATUS_RECYCLED						(0x1UL<<5UL)//currently in recycler cache
#define SESNSTATUS_DEFERRED_RECYCLE		(0x1UL<<6UL)//session marked as soft suspended and is ready to be recycled
#define SESNSTATUS_IDLED							(0x1UL<<7UL)//idle for longer than set idle period, did not respond to ping msg
#define SESNSTATUS_INSERVICE			    (0x1UL<<8UL)//curently being serviced by a thread
#define SESNSTATUS_SECURE		  			  (0x1UL<<9UL)//SSL
#define SESNSTATUS_IOERROR						(0x1UL<<10UL)//in msg queue
#define SESNSTATUS_LOCATED						(0x1UL<<11UL)//in location declated
#define SESNSTATUS_MIGRATED						(0x1UL<<12UL)//session was migrated from another backend
#define SESNSTATUS_REMOTE							(0x1UL<<13UL)//session referenced by association, with which we don't maintain a direct connection with session
#define SESNSTATUS_REMOTE_CONNECTED		(0x1UL<<14UL)//remote and connected: we especially mark this, but otherwise we reuse SUSPENDED, RECYCLED,
#define SESNSTATUS_FENCELIST_LAZY			(0x1UL<<15UL)//remote user with incomplete fence list, being built on demand
#define SESNSTATUS_QUIT								(0x1UL<<16UL)//user quit on request or by the system after certain inactivity cycle
#define SESNSTATUS_RECYCLEREQUEST			(0x1UL<<17UL)//request to rerun session through Delegor IO cycle
#define SESNSTATUS_EPHEMERAL					(0x1UL<<18UL)//session is being serviced  outside the context of direct IO mode, eg by a worker thread
#define SESNSTATUS_UNDERCONSTRUCTION 	(0x1UL<<19UL)//session not fully built yet not all values assigned
#define SESNSTATUS_FAULTY							(0x1UL<<20UL)//session has faulty elements and cannot be used for I/O
#define SESNSTATUS_IPC								(0x1UL<<21UL)//session is of type IPC ie not regular IO worker session
#define SESNSTATUS_SNAPSHOT						(0x1UL<<22UL)//session that is purely used for data representation and therefore not connected or visible other than to creator
#define SESNSTATUS_CARRIER						(0x1UL<<23UL)//session that is not associatd with real user and not visible in hashes.
#define SESNSTATUS_TRANSIENT					(0x1UL<<24UL)//session is allocated for a new SessionWorker request as a temporary holder, until real session is located. Similar to Ephemeral for UfsrvWorker

typedef InstanceHolder InstanceHolderForSession;

enum SessionState {
  INVALID_COOKIE = 1,
  INVALID_CREDENTIALS,
  INVALID_USERNAME,
  INVALID_PASSWORD
};

//each protocol has two typesof data: type specific (one per type) and session specific (as many as requests)
//type is picked up from config file and can be specified on basis of combination of host/port
struct ServerSessionData {
	//fake type for readability
};
typedef struct ProtocolSessionData ProtocolSessionData;

struct ProtocolTypeData {
	//fake type for readability
};
typedef struct ProtocolTypeData ProtocolTypeData;

struct MessageQueue {
	 Queue queue;//used with SocketMessage
	 pthread_mutex_t mutex;
	 pthread_mutexattr_t mutex_attr;
 };
typedef struct MessageQueue MessageQueue;

 typedef struct Session {
	EnumSessionGeoGroup geogroup;
  time_t  when_suspended,
					when_serviced_start,//start of last service session
					when_serviced_end;	//end of last service session

  unsigned long session_id;/*IMPORTANT THIS VALUE IS HASHED DONT CHANGE offsetof(Session, session_id)*/
  unsigned long device_id;//unique installation number. For the future it is possible to have multiple sessions for multiple devices
  unsigned long eid;//most recent event is
  unsigned long recycler_id; //unique id within recycle
  char session_cookie[CONFIG_MAX_COOKIE_SZ+1];/* IMPORTANT THIS VALUE IS HASHED DONT CHANGE offsetof(Session, session_cookie) or dynamic generate without redefining hash table init params*/
  char *cm_token; //cloud messaging token bound by CONFIG_CM_TOKEN_SZ_MAX

  unsigned long stat;  /* status: FIRING_DQUAD, SUSPENDED, handshake */

  Socket *dsptr; /* destination socket */
  Socket *ssptr; /* source socket */
  int ipcpipe_fds[2];//delegator-worker self-pipe*/

  //TODO: migrate into thread context
  PersistanceBackend 			*persistance_backend;//loaded from thread-specific data at service time
  InstrumentationBackend 	*instrumentation_backend;//loaded from thread-specific data at service time
  UserMessageCacheBackend *usrmsg_cachebackend;
	FenceCacheBackend				*fence_cachebackend;
  MessageQueueBackend 		*msgqueue_backend;//msg queue publisher loaded from thread-specific data at service time
  DbBackend 							*db_backend;//sql db handle
  ThreadContext						*thread_ctx_ptr;

  //void *_session_service; //SessionService state information
  void *event_descriptor;//epoll

  void *protocol_registry;
  //this is at the moment is a pointer to indexed Protocol
  ProtocolTypeData			*protocol_type_data; //TODO: to replace protocol_registry above
  ProtocolSessionData 	*protocol_session_data; //augment ufsrv with protocol specific session data

  struct {
	  SSL *ssl;
  }	session_crypto;

  struct  {
		pthread_rwlock_t       rwlock;
		pthread_rwlockattr_t   rwattr;
  }	session_events;

  MessageQueue message_queue_in;
  MessageQueue message_queue_out;

  //pthread_t pid;

  SessionService sservice;

  //this is necessary for efficient handling of lists' initialisation states. Align with enum EnumShareListType
  struct {
  	bool	fences:1,
				 	profile:1,
					location:1,
					netstate:1,
					contacts:1,
					blocked:1,
					read_receipt:1,
					activity_state:1;

  				//add more
  } lists_init_state;

 } Session;

typedef struct InstanceContextForSession {
  InstanceHolderForSession *instance_sesn_ptr;
  Session *sesn_ptr;
} InstanceContextForSession;

 //special holder to encapsulate the state information that defines ephemeral mode for a given session
 typedef struct EphemeralModeDescription {
	 ThreadContext						*thread_ctx_ptr;
	 PersistanceBackend 			*pers_ptr;
	 UserMessageCacheBackend	*usrmsg_cachbackend_ptr;
	 FenceCacheBackend	 			*fence_cachbackend_ptr;
	 MessageQueueBackend 			*mq_ptr;
	 InstrumentationBackend 	*inst_ptr;
	 DbBackend								*db_backend;
 } EphemeralModeDescription;

//all x must be Session *
#define SESSION_SERVICE(x) (&(x->sservice))


#define NO_SESSION                            ((Session *)NULL)

//#define SESSION_PID(x)	(x->pid)
#define SESSION_ID(x)													(x->session_id)
#define SESSION_EID(x)												((x)->eid)
#define SESSION_STATUS(x)											(x->stat)
#define SESSION_LISTS_INIT_STATE(x)						((x)->lists_init_state)
#define SESSION_LISTS_INIT_STATE_FENCES(x)		(SESSION_LISTS_INIT_STATE(x).fences)
#define SESSION_LISTS_INIT_STATE_PROFILE(x)		(SESSION_LISTS_INIT_STATE(x).profile)
#define SESSION_LISTS_INIT_STATE_LOCATION(x)	(SESSION_LISTS_INIT_STATE(x).location)
#define SESSION_LISTS_INIT_STATE_NETSTATE(x)	(SESSION_LISTS_INIT_STATE(x).netstate)
#define SESSION_LISTS_INIT_STATE_CONTACTS(x)	(SESSION_LISTS_INIT_STATE(x).contacts)
#define SESSION_LISTS_INIT_STATE_BLOCKED(x)	(SESSION_LISTS_INIT_STATE(x).blocked)
#define SESSION_LISTS_INIT_STATE_READ_RECEIPT(x)	(SESSION_LISTS_INIT_STATE(x).read_receipt)
#define SESSION_LISTS_INIT_STATE_ACTIVITY_STATE(x)	(SESSION_LISTS_INIT_STATE(x).activity_state)
#define SESSION_DEVICEID(x)										(x->device_id)
#define SESSION_COOKIE(x)	                    (x->session_cookie)
#define SESSION_WHEN_SUSPENDED(x)	            (x->when_suspended)
#define SESSION_WHEN_SERVICE_STARTED(x)	      (x->when_serviced_start)
#define SESSION_WHEN_SERVICED(x)	            (x->when_serviced_end)
#define SESSION_HADDRESS(x)	                  (x->ssptr->haddress)
#define SESSION_HPORT(x)	(x->ssptr->hport)
#define SESSION_USER_ACCOUNTSTATUS(x) (x->sservice.user.account_status)
#define SESSION_USER_TTRIBUTES(x)	(x->sservice.user.user_details.attrs)
#define SESSION_USERID_TEMP(x) (x->sservice.user.user_details.user_id)
#define SESSION_USERID(x) (UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(x)))
#define SESSION_UFSRVUID(x) (x->sservice.user.user_details.uid.data)
#define SESSION_UFSRVUIDSTORE(x) (x->sservice.user.user_details.uid)
#define SESSION_USERNAME(x)	(x->sservice.user.user_details.user_name)
#define SESSION_USERPASSWORD(x)	(x->sservice.user.user_details.password)
#define SESSION_USERBOOLPREFS(x)	((x)->sservice.user.user_details.user_preferences.on_off)
#define SESSION_USERNICKNAME(x)	((x)->sservice.user.user_details.user_preferences.nickname)
#define SESSION_USERAVATAR(x)	((x)->sservice.user.user_details.user_preferences.avatar)
#define SESSION_USERE164NUMBER(x)	((x)->sservice.user.user_details.user_preferences.e164number)
#define SESSION_USER_PROFILE_KEY(x) (x)->sservice.user.user_details.profile_key
#define SESSION_BASEFENCE_LOCAL(x)	(x->sservice.user.user_details.base_fence_local_id)
#define SESSION_PROTOCOLSESSION(x) (x->protocol_session_data)
#define SESSION_PROTOCOLTYPE(x) (x->protocol_type_data)//should be cast to Protool *
#define SESSION_CUMMULATIVE_TR(x)	(x->ssptr->trbytes)
#define SESSION_CUMMULATIVE_RC(x)	(x->ssptr->rcbytes)
#define SESSION_INCREMENT_TR(x, y)	(x->ssptr->trbytes+=y)
#define SESSION_INCREMENT_RC(x, y)	(x->ssptr->rcbytes+=y)
#define SESSION_CMTOKEN(x) (x)->cm_token
#define SESSION_PERSISTANCE_BACKEND(x)	x->persistance_backend
#define SESSION_SESSION_BACKEND(x)	(x)->persistance_backend
#define SESSION_MSGQUEUE_BACKEND(x)	x->msgqueue_backend
#define SESSION_DB_BACKEND(x) x->db_backend
#define SESSION_INSTRUM_BACKEND(x)	x->instrumentation_backend
#define SESSION_USRMSG_CACHEBACKEND(x)	x->usrmsg_cachebackend
#define SESSION_FENCE_CACHEBACKEND(x)		x->fence_cachebackend

#define SESSION_THREAD_CONTEXT(x)			(x)->thread_ctx_ptr
#define SESSION_THCTX_OBJECT_STORE(x)		SESSION_THREAD_CONTEXT(x)->ht_ptr

#define SESSION_UFSRV_GEOGROUP(x)			(x)->geogroup
#define SESSION_BASELOC(x)						(x)->sservice.user.user_details.baseloc_prefix
#define SESSION_HOMEBASELOC(x)				(x)->sservice.user.user_details.home_baseloc_prefix

#define SESSION_USERPREF_ONOFF_SET(x, y, z)	((x)->sservice.user.user_details.user_preferences.on_off.y=(z))
#define SESSION_USERPREF_ONOFF_GET(x, y)	((x)->sservice.user.user_details.user_preferences.on_off.y)
#define SESSION_USERPREF_SHLIST_PROFILE(x)	((x)->sservice.user.user_details.user_preferences.sharelist_profile)
#define SESSION_USERPREF_SHLIST_PROFILE_PTR(x)	&((x)->sservice.user.user_details.user_preferences.sharelist_profile)
#define SESSION_USERPREF_SHLIST_LOCATION(x)	((x)->sservice.user.user_details.user_preferences.sharelist_location)
#define SESSION_USERPREF_SHLIST_LOCATION_PTR(x)	&((x)->sservice.user.user_details.user_preferences.sharelist_location)
#define SESSION_USERPREF_SHLIST_NETSTATE(x)	((x)->sservice.user.user_details.user_preferences.sharelist_netstate)
#define SESSION_USERPREF_SHLIST_NETSTATE_PTR(x)	&((x)->sservice.user.user_details.user_preferences.sharelist_netstate)
#define SESSION_USERPREF_SHLIST_READ_RECEIPT(x)	((x)->sservice.user.user_details.user_preferences.sharelist_read_receipt)
#define SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(x)	&((x)->sservice.user.user_details.user_preferences.sharelist_read_receipt)
#define SESSION_USERPREF_SHLIST_ACTIVITY_STATE(x)	((x)->sservice.user.user_details.user_preferences.sharelist_activity_state)
#define SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(x)	&((x)->sservice.user.user_details.user_preferences.sharelist_activity_state)
#define SESSION_USERPREF_SHLIST_BLOCKED(x)	((x)->sservice.user.user_details.user_preferences.sharelist_blocked)
#define SESSION_USERPREF_SHLIST_BLOCKED_PTR(x)	&(SESSION_USERPREF_SHLIST_BLOCKED((x)))
#define SESSION_USERPREF_SHLIST_CONTACTS(x)	((x)->sservice.user.user_details.user_preferences.sharelist_contacts)
#define SESSION_USERPREF_SHLIST_CONTACTS_PTR(x)	&(SESSION_USERPREF_SHLIST_CONTACTS((x)))

#define SESSION_RESULT_PTR(x)	&(x->sservice.result)
#define SESSION_SOCKET(x)	(x->ssptr)
#define SESSION_SOCKETFD(x)	(x->ssptr->sock)
#define	SESSION_SOCKETBLOCKSZ(x) (x->ssptr->blocksz)

 //these are the transitional in/out SocketMessage buffers (ie. not queueued) They don't have mutex lock associated with them
#define SESSION_INSOCKMSG_TRANS(x)	(x->ssptr->socket_msg)
#define SESSION_INSOCKMSG_TRANS_PTR(x)	&(x->ssptr->socket_msg)
#define SESSION_INSOCKMSG_TRANS_EMPTY(x)	(x->ssptr->socket_msg.holding_buffer_msg_size==0)
#define SESSION_OUTSOCKMSG_TRANS(x)	(x->ssptr->socket_msg_out)
#define SESSION_OUTSOCKMSG_TRANS_PTR(x)	&(x->ssptr->socket_msg_out)

 //these are the queued SocketMessage buffers, for both incoiming and outgoing. only incoming has lock activated
#define SESSION_INSOCKMSG(x)	(x->message_queue_in)
#define SESSION_INSOCKMSG_PTR(x)	&(x->message_queue_in)
#define SESSION_INSOCKMSG_QUEUE(x)	(x->message_queue_in.queue)
#define SESSION_INSOCKMSG_QUEUE_SIZE(x)	(x->message_queue_in.queue.nEntries)
#define SESSION_INSOCKMSG_QUEUE_PTR(x)	&(x->message_queue_in.queue)

#define SESSION_OUTSOCKMSG(x)	(x->message_queue_out)
#define SESSION_OUTSOCKMSG_PTR(x)	&(x->message_queue_out)
#define SESSION_OUTSOCKMSG_QUEUE(x)	(x->message_queue_out.queue)
#define SESSION_OUTSOCKMSG_QUEUE_SIZE(x)	(x->message_queue_out.queue.nEntries)
#define SESSION_OUTSOCKMSG_QUEUE_PTR(x)	&(x->message_queue_out.queue)

#define SESSION_HTTPSESN_REQUEST(x)	((HttpSession *)x->protocol_session_data)->request
#define SESSION_HTTPSESN_RESPONSE(x)	((HttpSession *)x->protocol_session_data)->response
#define SESSION_HTTPSESN_REQUEST_PTR(x)	&(((HttpSession *)x->protocol_session_data)->request)
#define SESSION_HTTPSESN_RESPONSE_PTR(x)	&(((HttpSession *)x->protocol_session_data)->response)
#define SESSION_HTTPSESN_SESSIONID(x)	((HttpSession *)x->protocol_session_data)->session_id
#define SESSION_HTTPSESN_SENDFILECTX(x)	((HttpSession *)x->protocol_session_data)->send_file_ctx
#define SESSION_HTTPSESN_SENDFILECTX_PTR(x)	&(((HttpSession *)x->protocol_session_data)->send_file_ctx)

#define SESSION_ULOCATION_BYSERVER(x) ((x)->sservice.user.user_details.user_location_by_server)
#define SESSION_ULOCATION_BYSERVER_PTR(x) (&((x)->sservice.user.user_details.user_location_by_server))
#define SESSION_ULOCATION_BYSERVER_INITIALISED(x) ((x)->sservice.user.user_details.user_location_by_server_initialised)
#define SESSION_ULOCATION_BYUSER(x) ((x)->sservice.user.user_details.user_location)
#define SESSION_ULOCATION_BYUSER_PTR(x) (&((x)->sservice.user.user_details.user_location))
#define SESSION_ULOCATION_BYUSER_INITIALISED(x) ((x)->sservice.user.user_details.user_location_initialised)
#define SESSION_GEOFENCE_LAST(x) ((Fence *)GetInstance((x)->sservice.user.geofence_last))
#define SESSION_GEOFENCE_LAST_INSTANCE(x) ((x)->sservice.user.geofence_last)
#define SESSION_GEOFENCE_CURRENT(x) ((Fence *)GetInstance((x)->sservice.user.geofence_current))
#define SESSION_GEOFENCE_CURRENT_INSTANCE(x) ((x)->sservice.user.geofence_current)

#define SESSION_FENCE_LIST(x)	(x->sservice.session_user_fence_list)
#define SESSION_FENCE_LIST_PTR(x)	&((x)->sservice.session_user_fence_list)
#define SESSION_FENCE_LIST_COUNT(x)	(x->sservice.session_user_fence_list.nEntries)
#define SESSION_FENCE_LIST_SIZE(x)	x->sservice.session_user_fence_list.nEntries
#define SESSION_INVITED_FENCE_LIST(x)	((x)->sservice.session_user_invited_fence_list)
#define SESSION_INVITED_FENCE_LIST_PTR(x)	&((x)->sservice.session_user_invited_fence_list)
#define SESSION_INVITED_FENCE_LIST_SIZE(x)	((x)->sservice.session_user_invited_fence_list.nEntries)
#define SESSION_IN_LISTENTRY(x)	((Session *)(x->whatever))

#endif /* SRC_INCLUDE_SESSION_TYPE_H_ */
