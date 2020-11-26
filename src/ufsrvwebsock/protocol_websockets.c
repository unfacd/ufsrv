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
#include <misc.h>
#include <recycler/recycler.h>
#include <ufsrv_core/protocol/protocol.h>
#include <ufsrv_core/protocol/protocol_io.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvwebsock/include/protocol_websocket_io.h>
#include <ufsrvwebsock/include/protocol_websocket_routines.h>
#include <fence.h>
#include <ufsrv_core/location/location.h>
#include <ufsrv_core/user/users.h>
#include <net.h>
#include <ufsrvcmd_parser.h>
#include <ufsrvcmd_data.h>//array of indexed callbacks
#include <ufsrvcmd_user_data.h>//array of ufsrvcmd for users indexed callbacks
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <ufsrv_core/user/user_backend.h>
#include <http_request.h>
#include <message.h>
#include <ufsrv_core/fence/fence_state.h>
#include <ufsrvuid.h>

//ype and array data defined in ufsrvcmd_data.h
const UfsrvCommand *const ufsrvcmd_server_bound_callbacks_ptr = ufsrvmd_server_bound_callbacks_array;//service commands originating client -> server
const size_t ufsrvcmd_maxidx = sizeof(ufsrvmd_server_bound_callbacks_array) / sizeof(UfsrvCommand);

const UfsrvCommandResponse *const ufsrvcmd_client_bound_callbacks_ptr = ufsrvcmd_client_bound_callbacks_array;//service commands originating server -> client
const size_t ufsrvcmd_user_maxidx = sizeof(ufsrvcmd_client_bound_callbacks_array) / sizeof(UfsrvCommandResponse);

extern const Protocol 	*const protocols_registry_ptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;
extern ufsrv *const masterptr;

static UFSRVResult *_ParseUfsrvCommandMessage (InstanceContextForSession *, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len) __attribute__((always_inline));
static UFSRVResult *_UfsrvCommandInvokeCommandCallback (InstanceContextForSession *, WebSocketMessage *wsm_ptr, size_t cmdidx) __attribute__((always_inline));
static UFSRVResult *_DecodeAndParseWebSocketWireMessage (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr, const UfsrvCommand *ufsrv_cmd_ptr, json_object *jobj_msg);

/**
 *  relay to a processing callback. replaces MarshalServiceCommandToClient() below
 *
 *
 */
UFSRVResult *
UfsrvCommandInvokeUserCommand (InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, WebSocketMessage *wsm_ptr_received, struct json_object *jobj_in, WireProtocolData *payload, unsigned req_cmd_idx)
{
	if (req_cmd_idx <= ufsrvcmd_user_maxidx) {
#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ISSUING A UFSRVCMD TO USER USING CMDIDX: '%u'", __func__, pthread_self(), ctx_ptr->sesn_ptr, req_cmd_idx);
#endif

    const UfsrvCommandResponse *p = NULL;

    p = (ufsrvcmd_client_bound_callbacks_ptr + (req_cmd_idx));
    if (IS_PRESENT(p)) {
      struct json_object *jobj  = NULL;

      //we allow the user to pass in null jobj,in which case we manage the creation and destruction of it
      if (IS_EMPTY(jobj_in))  jobj  = json_object_new_object();
      else                    jobj  = jobj_in;

      UFSRVResult *r_ptr = (*p->callback)(ctx_ptr, ctx_ptr_target, wsm_ptr_received, jobj, payload);

      if (IS_EMPTY(jobj)) json_object_put(jobj);

      return r_ptr;
    } else {
      syslog(LOG_ERR, "%s {pid:'%lu' o:'%p'}: pointer into UfsrvCommand array invalid: terminating...", __func__, pthread_self(), ctx_ptr->sesn_ptr);

      _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
    }
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 *  This is the final gateway before passing a message for transmission through socket. It uses the adapter envelope TransmissionMessage to abstract
 *  different type of message formats (Text, Protobuf (SocketMessageType)).
 *  @param tmsg_ptr: tmsg_ptr is not memory managed by this function. Caller must deallocate.
 *
 *  TransmissionMessage of type WebSocketMessage we allocate the msg_packed reference as opaque object and calculate length. We don't manage the
 *  deallocation of this object directly. Upon successful transmission it gets memory managed with regular free function.
 *
 *  TransmissionMessage of type Text we allocate msg_pack and calculate length. Owner must deallocate original msg string,
 *  Upon successful transmission msg_packed  gets memory managed with regular free function.
 *
 *  @dynamic_memory: allocates packed protobuf msg or strdup msg (if text).
 *   All references contained in TransmissionMessage will have been referenced in out.raw
 *  and managed separately
 *
 *  @dynamic_memory WebSocketRequest and WebSocketResponse contained objects are opaque and must be free'd where they originated
 *
 *  @call_flag CALL_FLAG_DONT_LOCK_SESSION: (NOT IN USE) if set, target session won't be locked, as it is assumed locked by the caller
 *
 *  @locked sesn_ptr_this:
 *  @locks sesn_ptr_target:		unless CALL_FLAG_DONT_LOCK_SESSION
 *  @unlocks sesn_ptr_target: unless CALL_FLAG_DONT_LOCK_SESSION
 */
int
UfsrvCommandMarshalTransmission (InstanceContextForSession *ctx_ptr_this, InstanceContextForSession *ctx_ptr_target, TransmissionMessage *tmsg_ptr, unsigned long call_flags)
{
  bool 										lock_already_owned	= false;
  HttpRequestContext 			*http_ptr		=	NULL;
  InstanceContextForSession *ctx_ptr  = NULL;
  Session 								*sesn_ptr		=	NULL;

  ctx_ptr = ctx_ptr_this;
  sesn_ptr = ctx_ptr->sesn_ptr;

  lock_target_session:
  if (IS_PRESENT(ctx_ptr_target)) {
    if (!(call_flags&CALL_FLAG_DONT_LOCK_SESSION)) { //todo: this flag is currently not use
      SessionLockRWCtx(THREAD_CONTEXT_PTR, ctx_ptr_target->sesn_ptr, _LOCK_TRY_FLAG_TRUE, __func__);

      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
        return 0;
      }
      lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
    }

    sesn_ptr = ctx_ptr_target->sesn_ptr; //locked herein if CALL_FLAG_DONT_LOCK_SESSION wasn't set
  } else {
    sesn_ptr = ctx_ptr_this->sesn_ptr; //locked in calling environment
  }

  if (SESNSTATUS_IS_SET(ctx_ptr_this->sesn_ptr->stat, SESNSTATUS_EPHEMERAL)) {
    http_ptr = GetHttpRequestContextUfsrvWorker(ctx_ptr_this->sesn_ptr);
    if (IS_PRESENT(ctx_ptr_target))		SessionLoadEphemeralMode(ctx_ptr_target->sesn_ptr);
  } else {
    if (IS_PRESENT(ctx_ptr_target))	SessionTransferAccessContext (ctx_ptr_this->sesn_ptr, ctx_ptr_target->sesn_ptr, 0);
    http_ptr = GetHttpRequestContext(ctx_ptr_this->sesn_ptr);
  }

  //block: setup request envelope
  int rescode = 1;

  if (tmsg_ptr->type == TRANSMSG_PROTOBUF) {
    tmsg_ptr->len = web_socket_message__get_packed_size((WebSocketMessage *)tmsg_ptr->msg);
    tmsg_ptr->msg_packed = calloc(1, tmsg_ptr->len);
    web_socket_message__pack((WebSocketMessage *)tmsg_ptr->msg, tmsg_ptr->msg_packed);
  } else if (tmsg_ptr->type == TRANSMSG_TEXT) {
    tmsg_ptr->msg_packed = strdup((char *)tmsg_ptr->msg);//owner should free tmsg_ptr->msg
    tmsg_ptr->len = strlen(tmsg_ptr->msg);
  }

  //retain a copy
  unsigned char 	msg_packed_copy[tmsg_ptr->len];
  size_t 				msg_packed_copy_sz = tmsg_ptr->len;
  memcpy(msg_packed_copy, tmsg_ptr->msg_packed,  msg_packed_copy_sz);

  if ((tmsg_ptr->eid > 0) && _PROTOCOL_CTL_CLOUDMSG_ON_IOERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
    StoreStagedMessageCacheRecordForUser(sesn_ptr, tmsg_ptr, IS_PRESENT(ctx_ptr_target)?SESSION_USERID(ctx_ptr_target->sesn_ptr):SESSION_USERID(sesn_ptr));

  if	((SESSION_SOCKETFD(sesn_ptr) <= 0) || (SendToSocket(InstanceHolderFromClientContext(sesn_ptr), tmsg_ptr, 0) < 0)) { //0 means partial writeso it is not error
    if ((tmsg_ptr->eid > 0) && _PROTOCOL_CTL_CLOUDMSG_ON_IOERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
      UfsrvCommandMarshalCloudMessagingNotification(sesn_ptr, http_ptr, NULL); //TODO: enable GCM: temporarily disable to aid with valgrind

    rescode = -1;
    goto return_restore;
  } else {
    if ((tmsg_ptr->eid > 0) && _PROTOCOL_CTL_CLOUDMSG_ON_IOERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
      DeleteStagedMessageCacheRecordForUser(sesn_ptr, tmsg_ptr, IS_PRESENT(ctx_ptr_target)?SESSION_USERID(ctx_ptr_target->sesn_ptr):SESSION_USERID(sesn_ptr));
  }

  return_restore:
  if (IS_PRESENT(ctx_ptr_target)) {
    if (SESNSTATUS_IS_SET(ctx_ptr_this->sesn_ptr->stat, SESNSTATUS_EPHEMERAL))	SessionUnLoadEphemeralMode(ctx_ptr_target->sesn_ptr);
    if (!(call_flags&CALL_FLAG_DONT_LOCK_SESSION))	if (!lock_already_owned)	SessionUnLockCtx (THREAD_CONTEXT_PTR, ctx_ptr_target->sesn_ptr, __func__);
  }

  return  rescode;

}

void
ResetWebSocketProtocolSession (WebSocketSession *ws_ptr, bool is_self_destruct)
{
  if (IS_PRESENT(ws_ptr)) {
    if (IS_PRESENT(ws_ptr->protocol_header.key1)) {
      free(ws_ptr->protocol_header.key1);
      LOAD_NULL(ws_ptr->protocol_header.key1);
    }

    if (is_self_destruct) {
      free(ws_ptr);
    }
  }
}

/**
 * 	@brief: Relies on the presence of the "dry_run":true param to test if the token is valid without actually contacting the end user.
 * 	Defaults to false. Useful for checking if the app was uninstalled, hence we'd be in a position suspend user's account.
 */
bool
IsUserCloudRegistered (Session *sesn_ptr, HttpRequestContext *http_ptr)
{
#define GCM_DRYRUN_REQUEST_JSON	"{\"to\":\"%s\", \"dry_run\":true, \"data\": { \"notification\":\"yes\"} }"
	int 	rescode				=	RESCODE_PROG_NULL_POINTER;
	char 	json_payload[sizeof(GCM_DRYRUN_REQUEST_JSON)+CONFIG_CM_TOKEN_SZ_MAX]	= {0};
	char 	*gcm_id				=	NULL;

	if (!IS_STR_LOADED(SESSION_CMTOKEN(sesn_ptr))) {
	  ReloadCMToken(sesn_ptr, NULL);

	  if (IS_EMPTY(SESSION_CMTOKEN(sesn_ptr)))  goto return_db_error;
	}

	gcm_id=SESSION_CMTOKEN(sesn_ptr);
	snprintf(json_payload, (sizeof(GCM_DRYRUN_REQUEST_JSON)+CONFIG_CM_TOKEN_SZ_MAX)-1, GCM_DRYRUN_REQUEST_JSON, gcm_id);


	int result = HttpRequestGoogleGcm(http_ptr, APIURL_GOOGLE_GCM, json_payload);

	if (result == 0)	goto return_gcm_error;

	return_success:
	return true;

	return_gcm_error:
	syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid'%lu'): ERROR: COULD NOT POST json_payload '%s'. gcm_id:'%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_payload, gcm_id);
	goto return_error;

	return_db_error:
	syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid'%lu'): ERROR: COULD NOT GET GCM_ID FOR USER", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

	return_error:
	return false;
}

/**
 * @param sesn_ptr: must be Session owner with full backend access context
 */
UFSRVResult *
UfsrvCommandMarshalCloudMessagingNotification (Session *sesn_ptr, HttpRequestContext *http_ptr, WireProtocolData *data)
{
	if (IS_EMPTY(sesn_ptr))	goto return_generic_error;

	#define GCM_REQUEST_JSON	"{\"to\":\"%s\", \"data\": { \"notification\":\"yes\"} }"
	int 	rescode				=	RESCODE_PROG_NULL_POINTER;
	char 	json_payload[sizeof(GCM_REQUEST_JSON)+CONFIG_CM_TOKEN_SZ_MAX]	= {0};
	char 	*gcm_id				=	NULL;

  if (IS_EMPTY(SESSION_CMTOKEN(sesn_ptr))) {
    ReloadCMToken(sesn_ptr, NULL);

    if (IS_EMPTY(SESSION_CMTOKEN(sesn_ptr)))  goto return_db_error;
  }

	gcm_id=SESSION_CMTOKEN(sesn_ptr);
	snprintf(json_payload, (sizeof(GCM_REQUEST_JSON) + CONFIG_CM_TOKEN_SZ_MAX) - 1, GCM_REQUEST_JSON, gcm_id);

#if 0
	asprintf(&json_payload, "{\"to\":\"%s\", "
					 	 	 	 	 	 	 	 	 //"\"notification\": {\"body\":\"body_hello\", \"title\":\"title_hello\"} }",  gcm_id);
					 	 	 	 	 	 	 	 "\"data\": { \"notification\":\"yes\"} }",  gcm_id);//
#endif
	//HttpRequestContext *http_ptr=GetHttpRequestContextUfsrvWorker(sesn_ptr);

	int result = HttpRequestGoogleGcm(http_ptr, APIURL_GOOGLE_GCM, json_payload);

	if (result == 0)	goto return_gcm_error;

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode)

	return_gcm_error:
	syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid'%lu'): ERROR: COULD NOT POST json_payload '%s'. gcm_id:'%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_payload, gcm_id);
	statsd_inc(sesn_ptr->instrumentation_backend, "gcm.delivery.failed", 1.0);
	goto return_error;

	return_db_error:
	syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid'%lu'): ERROR: COULD NOT GET GCM_ID FOR USER", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

#if 0
		//curl --header "Authorization: key=xxx" --header "Content-Type:application/json" https://android.googleapis.com/gcm/send -d "{\"registration_ids\":[\"APA91bFaBGQMQQ8XzNlo1Zw86e8e8IpbiJF1xXbFlcQul2TtcTg9oymXImN3FBhpuocYGeFILssTxh6paB8WwEfZdi1kLmqepfguB7yXnUTMc2bdw5Tq2IWR71stpmtcpFtvyNp9tGBY\"] \"message\":\"hellow\"}"
//curl --header "Authorization: key=xxx
//" --header "Content-Type:application/json" https://android.googleapis.com/gcm/se
//nd -d "{\"registration_ids\":[\"APA91bFaBGQMQQ8XzNlo1Zw86e8e8IpbiJF1xXbFlcQul2Tt
//cTg9oymXImN3FBhpuocYGeFILssTxh6paB8WwEfZdi1kLmqepfguB7yXnUTMc2bdw5Tq2IWR71stpmtc
//pFtvyNp9tGBY\"] \"message\":\"hellow\"}" --insecure

		//response
		//{"multicast_id":6126472261424557086,"success":1,"failure":0,"canonical_ids":1,"results":[{"registration_id":"APA91bEW6clA02RI2S_4caipD1k-SotCMjCbdrwrHWeNcxAPBG7Pra3ermvKN-gn9bi_rY4l6iTEZ3gPqYZyaW5V_hpZKv9JOn1IoPo5aHTobzaAb1lJHpST0PT3Y0Dx-iTnV3eFKKWm","message_id":"0:1478614820005773%3af43603f9fd7ecd"}]}
#endif

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	return_generic_error:
	return _ufsrv_result_generic_error;
}

UFSRVResult *
proto_websocket_protocol_init_callback (Protocol *proto_ptr)
{
	syslog (LOG_INFO, "%s: Initialising WebSocket Protocol...", __func__);

	InitUFSRV();
	CreateSessionsDelegatorThread ();

	InitFenceRecyclerTypePool();
	InitFenceStateDescriptorRecyclerTypePool();

	InitialiseMaserFenceRegistries();
	InitialiseMasterUserRegistry();

	InitialiseScheduledJobTypeForOrphanedFences();

	RegisterFenceUserPreferencesSource ();
	RegisterUserPreferencesSource ();

	return NULL;
}

UFSRVResult *
proto_websocket_init_listener (void)
{
	int socket;
	static UFSRVResult res = {0};

	if ((socket = SetupListeningSocket(masterptr->main_listener_address, masterptr->listen_on_port, SOCK_TCP, SOCKOPT_IP4|SOCKOPT_REUSEADDRE)) > 0) {
		Socket *s_ptr = calloc(1, sizeof(Socket));

		s_ptr->type = SOCK_MAIN_LISTENER;
		s_ptr->sock = socket;
		strcpy (s_ptr->address, masterptr->main_listener_address);
		strcpy (s_ptr->haddress, masterptr->main_listener_address);

		syslog(LOG_INFO, "%s: Successfully created Main Listener on %s:%d (fd:'%d')...", __func__, masterptr->main_listener_address, masterptr->listen_on_port, s_ptr->sock);

		res.result_user_data = s_ptr;
		res.result_type = RESULT_TYPE_SUCCESS;
	} else {
		syslog(LOG_INFO, "%s: ERROR: COULD NOT CREATE MAIN LISTENER SOCKET port %d (%s, fd:'%d')...", __func__, masterptr->listen_on_port, strerror(errno), socket);
		res.result_user_data = NULL;
		res.result_type = RESULT_TYPE_ERR;
	}

	return &res;

}

//TODO: this may need to be phased out
UFSRVResult *
proto_websocket_init_workers_delegator_callback (void)
{
	//CreateSessionsDelegatorThread ();

	return _ufsrv_result_generic_success;
}

UFSRVResult *
proto_websocket_main_listener_callback (Socket *sock_ptr_listener, ClientContextData *context_ptr)
{
	UfsrvMainListener (sock_ptr_listener, (Socket *)context_ptr); //this never really returns

	return _ufsrv_result_generic_success;
}

UFSRVResult *
proto_websocket_hanshake_callback (InstanceHolder *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned callflags, int **comeback)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	UFSRVResult *res_ptr = ProcessIncomingWsHandshake(sesn_ptr, sock_msg_ptr);
	switch (res_ptr->result_type)
	{
		case RESULT_TYPE_ERR:
			if (res_ptr->result_code == RESCODE_IO_WOULDBLOCK) {
			} else if (res_ptr->result_code == RESCODE_IO_CONNECTIONCLOSED) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}:  COULD NOT HANDSHAKE: connection closed", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));
			} else if (res_ptr->result_code == RESCODE_PROTOCOL_WSHANDSHAKE) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}:  COULD NOT HANDSHAKE: parsing error", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));
			}

			SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_WSHANDSHAKE)

}

/*
 * 	@brief: Session has just been successfully handshaked both ways and authenticated. This session could be brand new, migrated, unsuspended etc...
 */
UFSRVResult *
proto_websocket_post_hanshake_callback (InstanceHolder *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned callflags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//TODO: authenticated_user check for return
	//MarshalServiceCommandToClient(sesn_ptr_hashed, NULL, 1);//authenticated user
	DetermineUserLocationByServer (sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event

  UfsrvCommandInvokeUserCommand(&(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr}, NULL, NULL, NULL, NULL,
                                uSTATESYNC_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
 
}

static inline UFSRVResult *
_UfsrvCommandInvokeCommandCallback (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr, size_t cmdidx)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

		//type safety guaranteed
	if (cmdidx <= ufsrvcmd_maxidx) {
		const UfsrvCommand *p = NULL;
		UFSRVResult *ufsrv_res;

		struct json_object *jobj = NULL;
		enum json_tokener_error jerr;
		const char *json_str;
		size_t json_str_len = 0;

		//we have a json payload included
		if ((json_str = wsm_ptr->request->verb)) {
			json_str_len  = strlen(json_str);
		}

		if (json_str_len) {
			struct json_tokener *jtok;

#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): TOKENISING JSON: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_str);
#endif
			jtok = json_tokener_new();

			do {
				jobj = json_tokener_parse_ex(jtok, json_str, json_str_len);
			} while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

			if (jerr != json_tokener_success) {
				syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): JSON tokeniser Error: '%s'...", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_tokener_error_desc(jerr));

				jobj = NULL;
			}

			json_tokener_free(jtok);
		}

		if ((p = (ufsrvcmd_server_bound_callbacks_ptr + cmdidx))) {
			if ((json_str_len) && (jerr == json_tokener_success)) {
			//>>>>>>>>>>>>>>>>>>>>>>>>>>>>
			// ufsrv_res = (*p->callback)(ctx_ptr, wsm_ptr, jobj);
			 ufsrv_res = _DecodeAndParseWebSocketWireMessage(ctx_ptr, wsm_ptr, p, jobj);
			//>>>>>>>>>>>>>>>>>>>>>>>>>>>

			 json_object_put(jobj);
			} else {
				ufsrv_res = (*p->callback)(ctx_ptr, wsm_ptr, NULL);
			}

			return ufsrv_res;
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * '{"destination":"+61414821358","messages":[{"body":null,"content":"Mwi..3voB","destinationDeviceId":1,"destinationRegistrationId":0,"type":3}],"relay":null,"timestamp":1471608758401}'
 * @param wire_message
 */
static UFSRVResult *
_DecodeAndParseWebSocketWireMessage (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr, const UfsrvCommand *ufsrv_cmd_ptr, json_object *jobj_msg)
{
  int 				jobj_array_size		= 0;
  const char 	*destination			= json_object_get_string(json__get(jobj_msg, "destination"));
  time_t 			msg_timestamp			= json_object_get_int64(json__get(jobj_msg, "timestamp"));
  json_object	*jobj_messages_array	= json__get(jobj_msg, "messages");

  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if (unlikely((IS_EMPTY(jobj_messages_array)))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: No message found", __func__, pthread_self(), ctx_ptr->sesn_ptr);
    goto request_error;
  }
  if  (unlikely((jobj_array_size = json_object_array_length(jobj_messages_array)) == 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: zero message list found", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  }

  int					i;
  json_object	*jobj_entry = NULL;
  UFSRVResult *res        = _ufsrv_result_generic_error;

  for (i=0; i<jobj_array_size; i++) {
    jobj_entry = json_object_array_get_idx (jobj_messages_array, i);
    if (IS_PRESENT(jobj_entry)) {
      int device_id = json_object_get_int(json__get(jobj_entry, "destinationDeviceId"));
      int rego_id = json_object_get_int(json__get(jobj_entry, "destinationRegistrationId"));

      const char *msg_body_b64 = json_object_get_string(json__get(jobj_entry, "content"));

      if (!IS_STR_LOADED(msg_body_b64)) {
        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: MSG BODY IS MISSING...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
        break;
      }

      int rc_len = 0;
      char *msg_content_decoded = (char *) base64_decode((unsigned char *) msg_body_b64, strlen(msg_body_b64), &rc_len);
      if (IS_EMPTY(msg_content_decoded)) {
        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT b64-DECODE BODY MSG...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
        break;
      }

      DataMessage *dm_ptr = data_message__unpack(NULL, rc_len, (unsigned char *) msg_content_decoded);
      if (unlikely(IS_EMPTY(dm_ptr))) {
        free(msg_content_decoded);
        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT PROTOBUF-UNPACK DataMessage...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
        break;
      }

      res = (*ufsrv_cmd_ptr->callback)(ctx_ptr, wsm_ptr, dm_ptr);
//      FenceCommand *fcmd_ptr = dm_ptr->ufsrvcommand->fencecommand;
//
//      if (!(IS_EMPTY(fcmd_ptr))) {
////        UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA(dm_ptr), MSGCMD_FENCE, INTRA_SEMANTICS, (const unsigned char *)msg_body_b64);
//      } else {
//        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d'}: ERROR: NO FENCE COMMAND WAS PRESENT", __func__, pthread_self(), sesn_ptr, device_id);
//        free (msg_content_decoded);
//        data_message__free_unpacked(dm_ptr, NULL);
//        break;
//      }

      free(msg_content_decoded);
      data_message__free_unpacked(dm_ptr, NULL);
    }
  }

  return res;

  request_error:
  return _ufsrv_result_generic_error;
}

//TODO: we kind of mirroring what MarshalServiceCommandToClient is doing. We should consolidate at some stage

//This is reference as callback in protocol.h. If signature change, it needs to change there as well.
//TODO: frame_offset and len parameters are no longer applicable. frame_offset should be used as callflags by the calling environment
UFSRVResult *
proto_websocket_msg_callback (InstanceHolder *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
	ssize_t read_result;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	read_result = ReadFromSocket (instance_sesn_ptr, sock_msg_ptr, frame_offset);//frame_offset is 'callflags' passed by the calling environment

	if (read_result > 0)	goto process_framed_decoded_msg;
	else if (read_result == 0) {//if we are reading a very large frame, the first fragment will be seen by decode_hybi, which will return 0
		//subsequent reads will detect missing size and will continue to report zero until  full frame is recieved up to 65k which is the max frame zize we allowe for Websocket
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED: (frame_coundt='%lu' missing_msg_size: '%lu') RETURNING...", __func__,pthread_self(), SESSION_ID(sesn_ptr), sock_msg_ptr->frame_count, sock_msg_ptr->missing_msg_size);

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION)
	} else {
		read_error:
		switch (read_result)
		{
		case -1:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED)//suspended

		case -2:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)

		case -3://user sent termination in WS
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED)

		case -4:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_DECODED)//this fatal couldent base64 decode: suspend

		case -5:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MISSGINGFRAMEDATA)//benign error couldn't process frame because of incomplete frame data

		default:
			_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}
	}

	process_framed_decoded_msg:

	//TODO: this may be redundant as read_result==0 condition above should indicate the same condition
	if (sock_msg_ptr->frame_count == 0) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO FRAME WAS FOUND: NO MSG WILL BE PROCESSED: (missing_msg_size: '%lu') RETURNING...", __func__, pthread_self(), SESSION_ID(sesn_ptr), sock_msg_ptr->missing_msg_size);

		//TODO: FIX: this should be considered an error condition?
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION)
	}

	//start framed_decoded_msg
	{
		unsigned 	loop_counter								=	sock_msg_ptr->frame_count;
		const 		ProtocolCallbacks *const pc	=	&(((Protocol *)sesn_ptr->protocol_registry)->protocol_callbacks);
		size_t 		len													=	sock_msg_ptr->frame_index[0];//length of the first frame payload
		int 			frame_offset								=	0;
		UFSRVResult *ufcmd_result;

		while ((loop_counter--)) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p',  cid:'%lu'}: PARSE ITERATION: '%d': PAYLOAD length: '%lu' READING OFFSET '%d'...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), loop_counter+1, len, frame_offset);

			ufcmd_result = _ParseUfsrvCommandMessage (&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, sock_msg_ptr, frame_offset, len);
			switch (ufcmd_result->result_type)
			{
			case RESULT_TYPE_SUCCESS:
				if (ufcmd_result->result_code == RESCODE_IO_MSGPARSED) {
#ifdef __UF_FULLDEBUG
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESSFULLY INVOKED MSG CALLBACK...", __func__, pthread_self(), SESSION_ID(sesn_ptr));
#endif
				}
			break;

			case RESULT_TYPE_ERR:
				switch (ufcmd_result->result_code)
				{
					case RESCODE_IO_MSGPARSED:
						//processing or logical error
						syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'):  COULD NOT parse message...", __func__, pthread_self(), SESSION_ID(sesn_ptr));

						//TODO: implement trip threshold
						//ignore requestand send error status back to client
					break;	//to loop_processing_body

					case RESCODE_LOGIC_NOCMND:
					break;

					default:
						//network error
						if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)) {
							syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SESSION HAS BEEN SUSPENDED AMID ITERATION: PARSE ITERATION: '%d': READING OFFSET '%d': DISCONTINUING LOOP", __func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter+1, frame_offset);

							//TODO: do we break? or save the frame_offset where we left?we need to retry last msg?
						}
				}//inner switch
			break;//RESULT_TYPE_ERR

			}//outer switch

			loop_processing_body:
			//additional check just in case
			if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): OUTSIDE CONDITIONAL: SESSION HAS BEEN SUSPENDED AMID ITERATION: PARSE ITERATION: '%d': READING OFFSET '%d'...", __func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter+1, frame_offset);

				//TODO: do we break? or save the frame_offset where we left?we need to retry last msg?
				break;
			}

			if (loop_counter) {
			//only do it if loop_counter is >0 ie we have a subsequent run
				frame_offset += len;//remember last len

				if (frame_offset == sock_msg_ptr->processed_msg_size) {
					syslog(LOG_DEBUG, ">>>> %s (pid:'%lu' cid:'%lu'): MESG OFFSET EQUALS TOTAL MSG SIZE: loop_counter: '%u'. frame_offset='%d'. BREAKING LOOP", __func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter+1, frame_offset);
					break;
				}

				len = sock_msg_ptr->frame_index[sock_msg_ptr->frame_count - (loop_counter - 1)];//Increment offset to go past the '0'then read the length upto the next '0'
			}
		}//while

		//reset buffer
		cleanup_exit_block:
		free (sock_msg_ptr->_processed_msg);
		sock_msg_ptr->_processed_msg			=	0;
		sock_msg_ptr->processed_msg_size	=	0;
		sock_msg_ptr->frame_count					=	0;

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED)

	}//end framed_decoded_msg

}

UFSRVResult *
proto_websocket_decode_msg_callback (InstanceHolder *instance_sesn_ptr, SocketMessage *sm_ptr, unsigned frame_offset)
{
	unsigned int  opcode = 0,
	              left;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (sm_ptr->raw_msg_size == 0) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: Raw input buffer is empty: returning...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_DECODED)
	}

	sm_ptr->_processed_msg = calloc(1, sm_ptr->raw_msg_size);

	//this will tokenise multiple frames on '\0'
	//>>>>>>>>>>>>>>>>>>>>>>>>
	sm_ptr->processed_msg_size = decode_hybi(sm_ptr, sm_ptr->_raw_msg, sm_ptr->raw_msg_size, sm_ptr->_processed_msg, sm_ptr->raw_msg_size, &opcode, &left);
	//>>>>>>>>>>>>>>>>>>>>>>>>

	if (opcode == 8) {
		//orderly shutdown by client. all allocated buffers are cleared
		sm_ptr->processed_msg_size	=	1; //just to make sure buffer is correctly marked for destruction
		SuspendSession (instance_sesn_ptr, SOFT_SUSPENSE);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_PROTOCOL_SHUTDOWN)
	}

	if (sm_ptr->processed_msg_size < 0) {
		decoding_error:
		syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: COULD NOT DECODE MESSAGE. SocketMessage will be destructed. Connection  will be suspended", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		//buffer data is now unbalanced: get rid of it now in case the client becomes unsuspended and uses the buffer again
		sm_ptr->processed_msg_size	=	1; //just to make sure buffer is correctly marked for destruction
		DestructSocketMessage (sm_ptr); //this will free sm_ptr->_processed_msg even if its corresponding size is -1

		SuspendSession (instance_sesn_ptr, SOFT_SUSPENSE);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_DECODED)
	}

	//we have incomplete frame. cur_pos point to the begining of the incomplete frame in _processed_msg
	if (sm_ptr->missing_msg_size) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', cid:'%lu'): PARTIAL FRAME from client: amount left to be read: '%ld'. raw_msg_cur_pos='%ld'. holding_buffer_msg_size: '%ld' (This amount will be copied into holding_buffer). Raw buffer will be freed.",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sm_ptr->raw_msg_cur_pos, sm_ptr->holding_buffer_msg_size);

		//how much we managed to collect so far
		sm_ptr->holding_buffer = (unsigned char *)strndup((char *)(sm_ptr->_raw_msg+sm_ptr->raw_msg_cur_pos), sm_ptr->holding_buffer_msg_size);
	} else {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCESS: READ AND DECODED MESSAGE. size:  '%ld'. Raw buffer will be freed.", __func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->processed_msg_size);
#endif
	}

	//we are good. This buffer has been successfully utilised wholly or in part
	free (sm_ptr->_raw_msg);
	sm_ptr->_raw_msg			=	NULL;
	sm_ptr->raw_msg_size	=	0;

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_DECODED)

}

UFSRVResult *
proto_websocket_encode_msg_callback (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  sesn_ptr->ssptr->socket_msg_out.processed_msg_size = encode_hybi(&(sesn_ptr->ssptr->socket_msg_out),
                                                                    sesn_ptr->ssptr->socket_msg_out._raw_msg,
                                                                    sesn_ptr->ssptr->socket_msg_out.raw_msg_size,
                                                                    sesn_ptr->ssptr->socket_msg_out._processed_msg,
                                                                    sesn_ptr->ssptr->socket_msg_out.processed_msg_size,
                                                                    2);//binary not text 1);

		/*
		 * Two possibilities:
		 * for straight-through both raw and processed are the same reference: so we can free processed and zero out
		 * For WebSocket: raw and processed are both allocated so both must be freed
		 * However, this block is concerned with Websocket condition only
		 */
		if (sesn_ptr->ssptr->socket_msg_out.processed_msg_size < 0) {
			syslog(LOG_NOTICE, "%s: {pid:'%lu', th_ctx:'%p',  cid:'%lu'}: ERROR: COULD NOT ENCODE MSG...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_ENCODED)
		}

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_ENCODED)

}

/**
 * @brief: read processed buffer based on a given offset. This should be a complete, correctly decoded Websocket frame of size len.
 *
 * @returns RESULT_TYPE_ERR, RESCODE_LOGIC_NOCMND: command directive was missing. It is not an error for which we'd
 * terminate, but it should be counted as a "trip" indicator and a threashld is applied before terminating
 *
 * @returns RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED: this a desired success case
 *
 * @return RESULT_TYPE_ERR, RESCODE_IO_PROTOUNPACKING: packaging error
 */
static inline UFSRVResult *
_ParseUfsrvCommandMessage (InstanceContextForSession *ctx_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
	WebSocketMessage *wsm_ptr;

  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	if (*sock_msg_ptr->_processed_msg == '\0') {
    syslog(LOG_DEBUG, LOGSTR_PROTO_COMMAND_ENVELOPE_MISSING,  __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), frame_offset,  LOGCODE_PROTO_COMMAND_ENVELOPE_MISSING);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_NOCMND)
	}

	wsm_ptr = web_socket_message__unpack(NULL, len, sock_msg_ptr->_processed_msg + frame_offset);
	if (!IS_EMPTY(wsm_ptr)) {
		char *command = wsm_ptr->command;
		if (unlikely(!IS_STR_LOADED(command))) {
			syslog(LOG_DEBUG, LOGSTR_PROTO_COMMAND_MISSING,  __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), LOGCODE_PROTO_COMMAND_MISSING);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_NOCMND)
		}

		switch (wsm_ptr->type)
		{
      case WEB_SOCKET_MESSAGE__TYPE__REQUEST:
        ;//keep this empty statement for the declaration below to compile, or enclose with brackets
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', uname:'%s', command:'%s', id:'%lu'): Received WebSocket Request Command...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), command, wsm_ptr->request->id);
  #endif
        //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        int cmdidx = UfsrvCommandIndexGet(sesn_ptr, command);
        //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        _UfsrvCommandInvokeCommandCallback (ctx_ptr, wsm_ptr, cmdidx);

      break;

      //TODO: this shuld be merged with request. It is separated for debugging and semantics testing only
      case WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
  #ifdef __UF_TESTING
        syslog(LOG_NOTICE, "%s: (pid:'%lu', o:'%p', cid:'%lu'): >> UNSUPPORTED WEB_SOCKET_MESSAGE__TYPE__RESPONSE MESSAGE '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), wsm_ptr->response->message);
  #endif
        break;

      default:
        syslog(LOG_DEBUG, LOGSTR_PROTO_COMMAND_TYPE_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), command, wsm_ptr->type, LOGCODE_PROTO_COMMAND_TYPE_ERROR);
      }

      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED)
	} else {
		syslog(LOG_NOTICE, LOGSTR_PROTO_COMMAND_UNPACK_ERROR, __func__,pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), frame_offset, len, LOGCODE_PROTO_COMMAND_UNPACK_ERROR);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_PROTOUNPACKING)
	}

}

/**
 * @brief: Lifecycle callback for when a new session object is memory allocated. This is the pure data object, no instanceHolder
 *
 * @param call_flag: signifies whether the callback is being invoked from the context of the recycler. if set indicates the object is being initialised from a recycler GET request; ie recurring initiallisation. Otherwise indicates
 * object is being initialised at memory allocation time; ie once-off
 * setup
 *
 */
UFSRVResult *
proto_websocket_init_session_callback (ClientContextData *ctx_data_ptr, unsigned call_flags)
{
  Session *sesn_ptr = (Session *)ctx_data_ptr;

  if (call_flags == 0) {
    SESSION_PROTOCOLSESSION(sesn_ptr) = calloc(1, sizeof(WebSocketSession));
  } else {
    SESSION_PROTOCOLSESSION(sesn_ptr) = calloc(1, sizeof(WebSocketSession));
  }

  //TODO: at the moment the session object needs to be recreated regardless of recycler origin. Future optimisation

  common_init:

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 *
 * @param instance_sesn_ptr
 * @param call_flags signifies whether the callback is being invoked from the context of the recycler. If set indicates the object is being initialised from a recycler GET request; ie recurring initiallisation. Otherwise indicates
 * object is being initialised at memory allocation time; ie once-off
 * @return
 */
UFSRVResult *
proto_websocket_reset_callback (InstanceHolder *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  WebSocketSession *ws_ptr = (WebSocketSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (call_flags == 0) {
			if (IS_PRESENT(ws_ptr)) {
				syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid: '%lu'}: WEBSOCKET SESSION: DESTRUCTING OBJECT INSTANCE...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));
				if (IS_PRESENT(ws_ptr->protocol_header.key1)) {
				  free (ws_ptr->protocol_header.key1);
				  LOAD_NULL(ws_ptr->protocol_header.key1);
				}
			}
		} else {
			if (IS_PRESENT(ws_ptr)) {
			  //when invoked from within the recyrler SessionReset will have been invoked, clearing protocol session
				syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid: '%lu'}: WEBSOCKET SESSION: PUSHING TO RECYCLER...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));
			}
		}

  LOAD_NULL(SESSION_PROTOCOLSESSION(sesn_ptr));

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

#define BASELINE_REFCOUNT	3

/**
 * 	@brief: invoked everytime service timeout check is performed. This is invoked outside the normal Session worky context, hence
 * 	why ephemeral mode is loaded for the session.
 *
 * 	@param sens_ptr: this is a locally hashed session, but not necessarily connected. It will have ephemeral mode loaded.
 *
 * 	@locked sesn_ptr: locked by the caller unless the flag SESN_WONTLOCK is passed
 *
 * 	@worker: UfsrvWorker
 * 	@access_context sesn_ptr: loaded in ephemeral mode
 *
 * 	@returns on returning error, session will be suspended by the caller
 */
UFSRVResult *
proto_websocket_service_timeout_callback (InstanceHolder *instance_sesn_ptr, time_t now, unsigned long call_flags)
{
	bool recycle_flag = false;
	bool suspended_flag = false;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//local session with no handshake bit: perhaps connected then failed to complete the handshake
	if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE) && (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED))) {// || !SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED)))
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: CHECKING for Dangling Session with incomplete handshake (timeout='%u')...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.unauthenticated);
#endif
		//incomplete handshake
		if ((sessions_delegator_ptr->user_timeouts.unauthenticated > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.unauthenticated) {
			//even with dangling conditions are satisfied, we could still have lingering references, for example in the delegator-worker pipe, where a recycle request could have been raised before the session was subsequently suspended due to io error
			size_t session_refcount = SessionGetReferenceCount(instance_sesn_ptr);
			if (session_refcount > BASELINE_REFCOUNT) {
				//3 is the baseline state, as CheckSessionIdleTime() increases refcount. IMPORTANT: DECREASE TO '1' if CheckSessionIdleTime() removes the increase
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND REFERENCE-COUNTED Dangling Session WITH: Returning...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
				goto _return_noop;
			}

			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND Dangling Session: RECYCLING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
			if (SuspendSession(instance_sesn_ptr, HARD_SUSPENSE)) recycle_flag = true;
		}
	} else if  (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED) && SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Connected-Idling Session (timeout='%u')...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.connected, SESSION_ID(sesn_ptr));
#endif
		if ((sessions_delegator_ptr->user_timeouts.connected > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.connected) {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND Connected Idling Session: SUSPENDING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			if (SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
		}
		else if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_LOCATED)) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): CHECKING for LOCATION-LESS Session (timeout='%u'): 'cid='%lu'...", __func__, pthread_self(), sessions_delegator_ptr->user_timeouts.locationless, sesn_ptr->session_id);
#endif
			if ((sessions_delegator_ptr->user_timeouts.locationless > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.locationless) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND Connected-Location-less Session: SUSPENDING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

				if (SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
			}
		}
		/*else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): UNABLE TO ASCERTAIN THE STATE OF A CONNECTED SESSION: Forcibly suspending...",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			SuspendThisSession (NULL, sesn_ptr, 0); suspended_flag=true;
		}*/
	} else if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED) && (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Suspended Session (timeout:'%u'): 'cid='%lu'...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.suspended);
#endif
		if ((sessions_delegator_ptr->user_timeouts.suspended > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.suspended) {
			//even with above conditions are satisfied, we could still have lingering references, for example in the delegator-worker pipe, where a recycle request could have been raised before the session was subsequently suspended due to io error
			size_t session_refcount = SessionGetReferenceCount(instance_sesn_ptr);
			if (session_refcount > BASELINE_REFCOUNT) {
				//3 is the baseline state, as CheckSessionIdleTime() increases refcount. IMPORTANT: DECREASE TO '1' if CheckSessionIdleTime() removes the increase
				syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND REFERENCE-COUNTED Suspended Idling Session: Returning...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
				goto _return_noop;
			}

			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'): FOUND Suspended Idling Session: RECYCLING: ...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);

			if (SuspendSession(instance_sesn_ptr, HARD_SUSPENSE)) recycle_flag = true;
		}
	} else if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE)) {
		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'): FOUND REMOTE CONNECTED Session: IGNORING...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));
		} else {
#if 0
			//TODO: to be enabled at future date
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND REMOTE _NON_ CONNECTED &&& SUSPENDED Session: CLEARING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			ClearLocalSessionCache(NULL, sesn_ptr, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//we dont unlock
#endif
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', cid:'%lu'}: UNABLE TO ASCERTAIN THE STATE OF ORPHAN SESSION: Forcibly suspending...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, SESSION_ID(sesn_ptr));

		if (SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
	}

	if (recycle_flag)	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_HARDSPENDED)

	if (suspended_flag)	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_SOFTSPENDED)

	_return_noop:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
proto_websocket_error_callback (InstanceHolder *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  _return_noop:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
proto_websocket_recycler_error_callback (InstanceHolder *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  _return_noop:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
proto_websocket_close_callback (InstanceHolder *instance_sesn_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  _return_noop:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)
}

#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>

UFSRVResult *
proto_websocket_msgqueue_topics_callback(UFSRVResult *res_ptr)
{
	static char 								*topic_names[UFSRV_MAX_BROADCAST_ID];
	static CollectionDescriptor collection_topics;

	for (size_t i=0; i<UFSRV_MAX_BROADCAST_ID; i++) {
		UfsrvCommandBroadcast *broacast_ptr = GetBroadcastDescriptorByTopicId ((enum UfsrvCmdTopicIds) i);
		topic_names[i] = broacast_ptr->topic_name;
	}

	collection_topics.collection_sz = UFSRV_MAX_BROADCAST_ID;
	collection_topics.collection    = (collection_t **)topic_names;

	_RETURN_RESULT_RES(res_ptr, &collection_topics, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_DATA)

}