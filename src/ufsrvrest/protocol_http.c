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
#include <sessions_delegator_type.h>
#include <ufsrv_core/protocol/protocol.h>
#include <ufsrv_core/protocol/protocol_io.h>
#include <protocol_http.h>
#include <protocol_http_io.h>
#include <http_session_type.h>
#include <http_request_handler.h>
#include <net.h>
#include <request.h>
#include <url.h>
#include <h_handler.h>
#include <h_basic_auth.h>
#include <attachments.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <message.h>
#include <ufsrv_core/user/users.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/fence/fence_state.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern const Protocol			*const protocols_registry_ptr;
extern SessionsDelegator	*const sessions_delegator_ptr;

static void InitUfsrvApiEndpoints (void);

#include <api_endpoint_v1_account.h>
#include <api_endpoint_v1_call.h>
#include <api_endpoint_v1_registry.h>
#include <api_endpoint_v1_message.h>
#include <api_endpoint_v1_fence.h>
#include <api_endpoint_v1_user.h>
#include <api_endpoint_v1_receipt.h>
#include <api_endpoint_v1_server.h>

static void
InitUfsrvApiEndpoints (void)
{
	syslog(LOG_INFO, "%s: INITIALISING API ENDPOINTS...", __func__);

	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Nonce", 				(void *)NONCE);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Nickname/*", 	(void *)NICKNAME);

  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Captcha", 				(void *)CAPTCHA);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/SignOn", (void *)ACCOUNT_SIGNON);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/New", 		(void *)ACCOUNT_CREATENEW);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/VerifyNew/Voice/Script/*", (void *)ACCOUNT_VERIFYNEW_VOICESCRIPT);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/VerifyNew/Voice/*", (void *)ACCOUNT_VERIFYNEW_VOICE);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/VerifyNew", 	(void *)ACCOUNT_VERIFYNEW);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/VerifyStatus/*", (void *)ACCOUNT_VERIFYSTATUS);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Nonce", 			(void *)ACCOUNT_NONCE);
#ifdef __UF_TESTING
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/PasswordHash", (void *)ACCOUNT_GENERATEPASSWORDHASH);
#endif
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Attachment*", (void *)ACCOUNT_ATTACHMENT);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Keys", 				(void *)ACCOUNT_KEYS);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Keys/Status", 	(void *)ACCOUNT_KEYS_STATUS);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Keys/Signed", 	(void *)ACCOUNT_KEYS_SIGNED);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Keys/PreKeys/*", 	(void *)ACCOUNT_KEYS_PREKEYS);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/GCM", 							(void *)ACCOUNT_GCM);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Prefs/Group/*", 	(void *)PREFSGROUP);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Prefs/StickyGeogroup/*", 	(void *)PREFSSTICKY_GEOGROUP);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Prefs", 					(void *)PREFS);
  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Profile/*", 	(void *)PROFILE);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/SharedContacts", 	(void *)ACCOUNT_SHARED_CONTACTS);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Account/Devices*", 			  (void *)ACCOUNT_DEVICES);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/UserAttributes", 	(void *)ACCOUNT_USERATTRIBUTES);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/StateSync", 				(void *)STATESYNC);
  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Account/Certificate/Delivery",	(void *)CERTIFICATE_DELIVERY);

	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Call", 										(void *)CALL);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Call/Turn", 								(void *)CALL_TURN);

	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Receipt", 										(void *)RECEIPT);

	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Registry/UserToken/*", 		(void *)REGISTERY_USER);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Registry/UserId/*", 			(void *)REGISTERY_USERID);

  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/MessageNonce*", 							(void *)MESSAGE_NONCE);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Message/*", 							(void *)MESSAGE);
#ifdef __UF_TESTING
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Encrypt", (void *)MESSAGE_ENCRYPT);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Decrypt", (void *)MESSAGE_DECRYPT);
#endif

	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Fence/NearBy", (void *)FENCE_NEARBY);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Fence/Search/*", (void *)FENCE_SEARCH);
  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Fence/Certificate/*", (void *)FENCE_CERTIFICATE);
  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "V1/Fence/ZKGroup", (void *)FENCE_ZKGROUP);
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Fence/*", (void *)FENCE);

  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/User/Presence/*", 	(void *)USER_PRESENCE); //always put ahead of User below
	onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/User/*", 	(void *)USER);

  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Server/Certificate*", 	(void *)SERVER_CERTIFICATE);

  onion_url_add((onion_url *)HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTOCOLID_HTTP), "^V1/Server/ZKGroup/Params*", 	(void *)SERVER_ZKGROUP_PARAMS);

}/**/

/**
 *  @brief: One-off Protocol type data initialisation
 */
UFSRVResult *
proto_http_init_callback (Protocol *proto_ptr)
{
	Protocol *proto_ptr_my;
	ProtocolHttp *proto_http_ptr;

	InitUFSRV();
	CreateSessionsDelegatorThread ();

	//_GET_PROTO_HTTP(proto_ptr);
	proto_ptr_my = ProtocolGet (PROTOCOLID_HTTP);
	proto_http_ptr = calloc(1, sizeof(ProtocolHttp));
	_ASSIGN_PROTOCOL_TYPE_DATA(proto_ptr_my, proto_http_ptr);//connect the two pointers

	//AA+ HTTP
	syslog(LOG_INFO, "%s: ASSIGNED DEFAULT HTTP URL AND ERROR HANDLERS...", __func__);

	proto_http_ptr->http_handlers.internal_error_handler = onion_handler_new((onion_handler_handler)onion_default_error, NULL, NULL);

	proto_http_ptr->http_handlers.root_handler = (onion_handler *)onion_root_url();

	proto_http_ptr->constants.max_post_size = 1024*1024; // 1MB
	proto_http_ptr->constants.max_file_size = 1024*1024*1024; // 1GB


	//HTTP_PROTOCOL_MAXPOSTSIZE(protocols_registry_ptr);

	InitUfsrvApiEndpoints();
	proto_http_ptr->http_handlers.root_auth_handler = onion_handler_auth_pam("ufsrv api", NULL, proto_http_ptr->http_handlers.root_handler);

	InitFenceRecyclerTypePool();
	InitFenceStateDescriptorRecyclerTypePool();

	InitAttachmentDescriptorRecyclerTypePool();
	InitialiseAttachmentsHashTable ();
	InitialiseBasicAuthLruCache ();

	RegisterFenceUserPreferencesSource ();
	RegisterUserPreferencesSource ();

	return NULL;
}

UFSRVResult *
proto_http_config_callback (ClientContextData *config_file_handler_ptr)
{
	lua_getglobal(config_file_handler_ptr, "intra_ufsrv_classname");
	if (!lua_isstring((lua_State *)config_file_handler_ptr, -1)) {
		syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED VALUE SET FOR 'intra_ufsrv_classname': using default '%s'", __func__, _CONFIGDEFAULT_INTRA_UFSRV_CLASSNAME);
		strncpy (masterptr->intra_ufsrv_classname, _CONFIGDEFAULT_INTRA_UFSRV_CLASSNAME, MINIBUF);
	} else {
		strncpy(masterptr->intra_ufsrv_classname,(lua_tostring((lua_State *)config_file_handler_ptr, -1)), MINIBUF);
	}

	syslog(LOG_ERR, "%s: Config 'intra_ufsrv_classname' set to: '%s'", __func__, masterptr->intra_ufsrv_classname);

	return _ufsrv_result_generic_success;
}

UFSRVResult *
proto_http_init_listener (void)
{
	int socket;
	static UFSRVResult res = {0};

	if ((socket = SetupListeningSocket(masterptr->main_listener_address, masterptr->listen_on_port, SOCK_TCP, SOCKOPT_IP4|SOCKOPT_REUSEADDRE))) {
		Socket *s_ptr = calloc(1, sizeof(Socket));

		s_ptr->type = SOCK_MAIN_LISTENER;
		s_ptr->sock = socket;
		strcpy (s_ptr->address, masterptr->main_listener_address);
		strcpy (s_ptr->haddress, masterptr->main_listener_address);

		syslog(LOG_INFO, "%s: Successfully created Main Listener on %s:%d (fd=%d)...", __func__, masterptr->main_listener_address, masterptr->listen_on_port, s_ptr->sock);

		res.result_user_data = s_ptr;
		res.result_type = RESULT_TYPE_SUCCESS;
	} else {
		syslog(LOG_INFO, "%s: ERROR: COUL NOT create Command Console port %d (%s)...", __func__, masterptr->listen_on_port, strerror(errno));
		res.result_user_data = NULL;
		res.result_type = RESULT_TYPE_ERR;
	}

	return &res;

}

//TODO: this may need to be phased out
UFSRVResult *
proto_http_init_workers_delegator_callback(void)
{
	return _ufsrv_result_generic_success;
}

UFSRVResult *
proto_http_main_listener_callback(Socket *sock_ptr_listener, ClientContextData *context_ptr)
{

	UfsrvMainListener (sock_ptr_listener, (Socket *)context_ptr); //this never really returns

	return _ufsrv_result_generic_success;

}

/**
 * @brief: Lifecycle callback for when a new session object is memory allocated. This is the pure data object, no instanceHolder
 *
 * @param call_flag: if set indicates the object is being initialised from a recycler GET request; ie recurring initiallisation. Otherwise indicates
 * object is being initialised at memory allocation time; ie once-off
 * setup
 *
 */
UFSRVResult *
proto_http_init_session_callback(ClientContextData *ctx_data_ptr, unsigned call_flags)
{
	HttpSession *http_ptr;

  Session *sesn_ptr = (Session *)ctx_data_ptr;

	if (call_flags == 0) {//brand new, heap based instance
		http_ptr = calloc(1, sizeof(HttpSession));
		SESSION_PROTOCOLSESSION(sesn_ptr) = (ProtocolSessionData *)http_ptr;
	} else {
		http_ptr = calloc(1, sizeof(HttpSession));
		SESSION_PROTOCOLSESSION(sesn_ptr) = (ProtocolSessionData *)http_ptr;

		//TODO: at the moment the session object needs to be recreated regardless of recycler origin. Future optimisation
		//this is done is SuspendSession() as an overriding behaviour
		//existing instance we just prime request again with new allocation
		//http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	}

	common_init:
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED);
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_AUTHENTICATED);
	SESSION_SOCKETBLOCKSZ(sesn_ptr)  =masterptr->buffer_size;//set default read block size

	HTTPSESN_REQUEST(http_ptr).headers = onion_dict_new();
	onion_dict_set_flags(HTTPSESN_REQUEST(http_ptr).headers, OD_ICASE);
	HTTPSESN_SESSIONID(http_ptr) = SESSION_ID(sesn_ptr);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 *
 *	@brief: This is invoked as just before session's socket is closed. Following this call
 *	object will be marshaled into recycler.
 *	Currently, This is called from SuspendSession(0 which frees the HttpSession *.
 */
UFSRVResult *
proto_http_reset_session_callback(InstanceHolderForSession *instance_sesn_ptr, unsigned callflags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (callflags == 0) {
#if 0
		//we ignore soft reset
		if (http_ptr)
		{
			//soft
			//TODO consider lighter method
			//onion_request_clean(onion_request* req)
			//framework is responsible for freeing http_ptr
			syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP SESSION: DESTRUCTING OBJECT INSTANCE...", __func__, pthread_self(), SESSION_ID(sesn_ptr));

			onion_request_free(HTTPSESN_REQUEST_PTR(http_ptr));
			//onion_response_free(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr));//AA-
			onion_response_destruct(sesn_ptr);//AA+

			//release json object
			if (HTTPSESN_JSONDATA(http_ptr))
			{
				json_object_put(HTTPSESN_JSONDATA(http_ptr));
				HTTPSESN_JSONDATA(http_ptr)=NULL;
			}


			//this is done by SuspendSession regardless of recycler origin
			//SESSION_PROTOCOLSESSION(sesn_ptr)=NULL;
			//free(http_ptr);
		}
#endif
	} else {
		if (http_ptr) {
#ifdef __UF_FULLDEBUG
			syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP SESSION: PUSHING TO RECYCLER...", __func__, pthread_self(), SESSION_ID(sesn_ptr));
#endif
			onion_request_free(HTTPSESN_REQUEST_PTR(http_ptr));
			//onion_response_free(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr));//AA-
			onion_response_destruct(sesn_ptr);//A+

			//release json object
			if (HTTPSESN_JSONDATA(http_ptr)) {
				json_object_put(HTTPSESN_JSONDATA(http_ptr));
				HTTPSESN_JSONDATA(http_ptr) = NULL;
			}

			if (SESSION_PROTOCOLSESSION(sesn_ptr)) {
				free(SESSION_PROTOCOLSESSION(sesn_ptr));
				SESSION_PROTOCOLSESSION(sesn_ptr) = NULL;
			}
		}
	}

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

UFSRVResult *
proto_http_hanshake_callback(InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sm_ptr, unsigned callflags, int **comeback)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *proto_http_post_hanshake_callback (InstanceHolderForSession *instance_sesn_ptr)
{
	return _ufsrv_result_generic_success;
 
}

bool IsConnectionKeepAlive(Session *sesn_ptr)
{
	onion_request *req=SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr);
	onion_response *res=SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr);

			// keep alive only on HTTP/1.1.
	syslog(LOG_DEBUG, "%s: keep alive [req wants] %d && ([skip] %d || [lenght ok] %d==%d || [chunked] %d)", __func__,
			onion_request_keep_alive(req), res->flags&OR_SKIP_CONTENT,res->length, res->sent_bytes, res->flags&OR_CHUNKED);

	if (onion_request_keep_alive(req) &&
		 (res->flags&OR_SKIP_CONTENT || res->length==res->sent_bytes || res->flags&OR_CHUNKED)) return true;

	else	return false;

}

/**
 *  Handler returns the following:
 *  Procesed: the request was matched and processed -> connection will be closed
 *  KeepAlive: PROCESSED AND we we want to retain the connected for more future data
 *  NOT PROCESSED we terminate
 */
UFSRVResult *proto_http_msg_callback(InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
	ssize_t amount_read;
	int rescode;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if ((amount_read = ReadFromSocket(instance_sesn_ptr, sock_msg_ptr, frame_offset/*as flag*/)) > 0) {
		onion_connection_status st = onion_request_write(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr), (const char *)sock_msg_ptr->_processed_msg/*buffer*/, sock_msg_ptr->processed_msg_size/* len*/);

		if (st != OCS_NEED_MORE_DATA) {
			//the request was logically complete (e.g. complete file, or etc..)
			if (st == OCS_REQUEST_READY) {
				//invoke handlers
				st = onion_request_process(instance_sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)); // May give error to the connection, or yield or whatever.
				if (st == OCS_CLOSE_CONNECTION) {
					//success case singular connection
					rescode =	RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: HANDLER RETURN VALUE: '%d': TERMINATING CONNECTION...", __func__, pthread_self(), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				} else if(st == OCS_KEEP_ALIVE) {
					rescode = RESCODE_IO_MSGPARSED;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HTTP KEEPALIVE CONNECTION: WON'T TERMINATE CONNECTION...", __func__, pthread_self(), SESSION_ID(sesn_ptr));
					goto protocol_exit;
				} else {
					rescode = RESCODE_PROG_NULL_POINTER;
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: UNKNOWN HANDLER RETURN VALUE: '%d': TERMINATING CONNECTION...", __func__, pthread_self(), SESSION_ID(sesn_ptr), st);
					goto protocol_exit_terminal;
				}

			}//OCS_REQUEST_READY

			protocol_exit_terminal:
			SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);

			protocol_exit:
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode)
		} else {
			syslog(LOG_DEBUG, "%s (cid:'%lu'): HTTP HANDLER RETURNED 'OCS_NEED_MORE_DATA': WON'T TERMINATE CONNECTION...", __func__, SESSION_ID(sesn_ptr));
			goto fragmented_data;
		}

	} else if (amount_read == 0) {//if we are reading a very large frame, the first fragment will be seen by decode_hybi, which will return 0
		//subsequent reads will detect missing size and will continue to report zero until  full frame is recieved up to 65k which is the max frame zize we allowe for Websocket
		fragmented_data:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', rvbytes:'%lu', raw_msg_sz:'%lu' upload_sz:'*'}: COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED:  RETURNING...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_CUMMULATIVE_RC(sesn_ptr), sock_msg_ptr->raw_msg_size/*, HTTPProtoGetCurrentFileSize(SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr))*/);

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION)
	} else {
		read_error:
		switch (amount_read)
		{
		case -1:
			rescode = RESCODE_IO_CONNECTIONCLOSED; break;

		case -2:
			rescode = RESCODE_LOGIC_CANTLOCK;	break;

		case -3://user sent termination in WS
			rescode = RESCODE_IO_CONNECTIONCLOSED; break;

		case -4:
			rescode = RESCODE_IO_DECODED; break;

		case -5:
			rescode = RESCODE_IO_MISSGINGFRAMEDATA;	break;

		default:
			rescode = RESCODE_PROG_NULL_POINTER;
		}
	}

	exit_error:
	//NO DON'T: this is done in ReadSocket on read() <0
	//SuspendSession (sesn_ptr, 0);

	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, rescode)

}

UFSRVResult *proto_http_msg_out_callback(InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	int 						fd			= SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd;

	if (fd > 0) {
			switch (HttpSendFile(sesn_ptr))
			{
				case OCS_NEED_MORE_DATA:
#ifdef __UF_TESTING
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): HTTP HANDLER RETURNED 'OCS_NEED_MORE_DATA': WON'T TERMINATE CONNECTION...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION)

				case OCS_PROCESSED:
					SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd = 0;
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_SOFTSPENDED)//ask to suspend session

				case OCS_NOT_PROCESSED:
				case OCS_INTERNAL_ERROR:
				default:
					//upstream SuspendSession (sesn_ptr, 0);
					SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd = 0;
					_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}
	}

	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

#define BASELINE_REFCOUNT	3

/**
 * 	@worker:	ufsrv
 * 	@access_context sesn_ptr: loaded in ephemeral mode
 */
UFSRVResult *
proto_http_service_timeout_callback(InstanceHolderForSession *instance_sesn_ptr, time_t now, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	bool recycle_flag	=	false;
	bool suspended_flag	=	false;

	if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED) || !SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: CHECKING for Dangling Session with incomplete handshake (timeout='%u')...",
			__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.unauthenticated);
#endif
		//incomplete handshake
		if ((sessions_delegator_ptr->user_timeouts.unauthenticated > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.unauthenticated) {
			//even with dangling conditions are satisfied, we could still have lingering references, for example in the delegator-worker pipe, where a recycle request could have been raised before the session was subsequently suspended due to io error
			size_t session_refcount = SessionGetReferenceCount(instance_sesn_ptr);
			if (session_refcount > BASELINE_REFCOUNT) {
			  //3 is the baseline state, as CheckSessionIdleTime() increases refcount. IMPORTANT: DECREASE TO '1' if CheckSessionIdleTime() removes the increase
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND REFERENCE-COUNTED Dangling Session WITH : Returning...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
				goto _return_noop;
			}

			if (SuspendSession(instance_sesn_ptr, HARD_SUSPENSE)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND Dangling Session: RECYCLING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
				recycle_flag = true;
			}
		}
	}
	else
	if  (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED) && SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Connected-Idling Session (timeout='%u')...",
			__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.connected, SESSION_ID(sesn_ptr));
#endif
		if ((sessions_delegator_ptr->user_timeouts.connected > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.connected) {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', now:'%lu', end_time:'%lu', now2:'%lu'): FOUND Connected Idling Session: SUSPENDING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), now, sesn_ptr->when_serviced_end, time(NULL));

			if (SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
		} else if  (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_LOCATED)) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): CHECKING for LOCATION-LESS Session (timeout='%u'): 'cid='%lu'...",
				__func__, pthread_self(), sessions_delegator_ptr->user_timeouts.locationless, sesn_ptr->session_id);
#endif
			if ((sessions_delegator_ptr->user_timeouts.locationless > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.locationless) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND Connected-Location-less Session: SUSPENDING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

				SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);
				suspended_flag = true;
			}
		} else {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): UNABLE TO ASCERTAIN THE STATE OF A CONNECTED SESSION: Forcibly suspending...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			if (SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
		}

	}
	else
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED) && (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): CHECKING for Suspended Session (timeout:'%u'): 'cid='%lu'...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sessions_delegator_ptr->user_timeouts.suspended);
#endif
		if ((sessions_delegator_ptr->user_timeouts.suspended > 0) && (now - sesn_ptr->when_serviced_end) > sessions_delegator_ptr->user_timeouts.suspended) {
			//even with above conditions are satisfied, we could still have lingering references, for example in the delegator-worker pipe, where a recycle request could have been raised before the session was subsequently suspended due to io error
			size_t session_refcount=SessionGetReferenceCount(instance_sesn_ptr);
			if (session_refcount > BASELINE_REFCOUNT) {
			  //3 is the baseline state, as CheckSessionIdleTime() increases refcount. IMPORTANT: DECREASE TO '1' if CheckSessionIdleTime() removes the increase
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'}: FOUND REFERENCE-COUNTED Suspended Idling Session: Returning...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);
				goto _return_noop;
			}

			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', refcount:'%lu'): FOUND Suspended Idling Session: RECYCLING: ...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), session_refcount);

			if (SuspendSession(instance_sesn_ptr, HARD_SUSPENSE)) recycle_flag = true;
		}
	}
	else if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE)) {
		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED)) {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND REMOTE CONNECTED Session: IGNORING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		} else {
#if 0
			//TODO: to be enabled at future date
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND REMOTE _NON_ CONNECTED &&& SUSPENDED Session: CLEARING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			ClearLocalSessionCache(NULL, sesn_ptr, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//we dont unlock
#endif
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: UNABLE TO ASCERTAIN THE STATE OF ORPHAN SESSION: Forcibly suspending...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		if (SuspendSession (instance_sesn_ptr, SOFT_SUSPENSE)) suspended_flag = true;
	}

	if (recycle_flag)	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_HARDSPENDED)

	if (suspended_flag)	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_SOFTSPENDED)

	_return_noop:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Lifecycle callback invoked when IO error is encounteredandbefore Session is (soft) suspended.
 *  Protocol can use this occasion to flush out buffers cleanly. Socket i/o most likely unavailable. This may not
 * 	be an error from the protocols perspective.
 */
UFSRVResult *
proto_http_error_callback(InstanceHolderForSession *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	int rescode                 = RESCODE_PROG_NULL_POINTER;
	SocketMessage *sock_msg_ptr = SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr);//&sesn_ptr->ssptr->socket_msg;
	onion_connection_status st;

	if (SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)==NULL) {
		_LOGD(LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), RESCODE_PROG_INCONSISTENT_STATE, "Empty HttpRequest object");
		rescode=RESCODE_PROG_INCONSISTENT_STATE;

		goto exit_error;
	}

	st = onion_request_write(sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr), (const char *)sock_msg_ptr->_processed_msg/*buffer*/, sock_msg_ptr->processed_msg_size/* len*/);
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu') NOTICE: SESNSTATUS_IOERROR IS FALGGED: NOT PROCESSING FURTHER", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
	}

	//have to be careful with this as io flag is on
	if (st != OCS_NEED_MORE_DATA) {
		if (st == OCS_REQUEST_READY) {
			st = onion_request_process(instance_sesn_ptr, SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr)); // May give error to the connection, or yield or whatever.
			if (st == OCS_CLOSE_CONNECTION) {
				//success case singular connection
				rescode =	RESCODE_IO_MSGPARSED;
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): SUCCESS: HANDLER RETURN VALUE: '%d': TERMINATING CONNECTION...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), st);
			} else if(st == OCS_KEEP_ALIVE) {
				rescode = RESCODE_IO_MSGPARSED;
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'cid:'%lu'): HTTP KEEPALIVE CONNECTION: SHOULD BE KEPT AROUND FOR PEER RESUMPTION", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			} else {
				rescode = RESCODE_PROG_NULL_POINTER;
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: UNKNOWN HANDLER RETURN VALUE: '%d': TERMINATING CONNECTION...", __func__, pthread_self(), SESSION_ID(sesn_ptr), st);
			}
		}
	} else {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED: (frame_coundt='%lu' missing_msg_size: '%lu') RETURNING...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sock_msg_ptr->frame_count, sock_msg_ptr->missing_msg_size);
#endif
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_FRAGMENTATION)

	}

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, rescode)


}

UFSRVResult *
proto_http_recycler_error_callback(InstanceHolderForSession *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

UFSRVResult *
proto_http_close_callback(InstanceHolderForSession *instance_sesn_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

UFSRVResult *
proto_http_msgqueue_topics_callback (UFSRVResult *res_ptr)
{

	return NULL;

}

static UFSRVResult *_FenceCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_MessageCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *, const unsigned char *);
static UFSRVResult *_SessionCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_UserCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_CallCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_ReceiptCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_SyncCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);
static UFSRVResult *_LocationCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded);

/**
 * 	@brief: The main interface for ufsrvapi class servers to notify stateful ufsrv class servers about an endpoint command.
 * 	In most cases, no backend model data will have changed. However, it is possible to signal the processing semantics with broadcast semantics flag.
 *
 * 	Endpoint sender encasulates the context for the ufsrv command to be processed in a 'UfsrvCommandWire' format
 * 	which contains all supported commands. A command type will also be set to specify which command to apply.
 * 	UfsrvCommandWireitself is encapsulated in 'DataMessage'. Down thewire this is transmitted as b64 encoded string, which is
 * 	what we get in json.
 *
 * 	The situation is different for Session messages because they don't originate from endpoint Therefore there is no DataMessage, or
 * 	UfsrvCommandWire. The SessionMessage will be generically cast to 'WireProtocolData *'
 *
 *	@param data: The unpacked, binary  wire message as originally intended by the sender. For Fence and Message this is
 *	currently 'DataMessage' type. For Session it will be 'SessionMessage' type.
 *	@param rawmsg_b64encoded: text-encoded wire message as originally encoded by sender for json transmission
 * 	@param sesn_ptr: Session is in ephemeral state ie not connected to end client, but has backend context loaded
 */
UFSRVResult *UfsrvApiIntraBroadcastMessage (Session *sesn_ptr, WireProtocolData *data, UfsrvMsgCommandType msgcmd_type, enum BroadcastSemantics broadcast_semantics, const unsigned char *rawmsg_b64encoded)
{
	UfsrvInstanceDescriptor ufsrv_instance	=	{0};

	if (IS_PRESENT(GetUfsrvInstance(sesn_ptr, masterptr->intra_ufsrv_classname, SESSION_UFSRV_GEOGROUP(sesn_ptr), &ufsrv_instance)))  {//TODO: remove hardcode reference
		switch (msgcmd_type)
		{
		case MSGCMD_FENCE:
			return (_FenceCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		case MSGCMD_MESSAGE:
			return (_MessageCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		case MSGCMD_SESSION:
			return (_SessionCommandIntraMarshal(sesn_ptr, &ufsrv_instance, NULL, data, rawmsg_b64encoded));

		case MSGCMD_USER:
			return (_UserCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		case MSGCMD_CALL:
			return (_CallCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		case MSGCMD_RECEIPT:
			return (_ReceiptCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		case MSGCMD_SYNC:
			return (_SyncCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

    case MSGCMD_LOCATION:
      return (_LocationCommandIntraMarshal(sesn_ptr, &ufsrv_instance, ((DataMessage *)data)->ufsrvcommand, data, rawmsg_b64encoded));

		default:
			break;
		}

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * @brief: forward a FenceCommand to the ufsrv processing environment. This is designed to work with ephemeral Sessions, ie not
 * not serviced by a io worker thread and therefore my not be connected to the end-client.
 * The actual payload is enveloped in MessageQueueMessage format which is what is used for MessaeQueue Bus inter-message broadcasts.
 * A copy of this will also be stored in staged area against the geogroup.
 *
 * @param sesn_ptr: this session is not connected to the end user
 *
 * @dynamic_memory: redis reply is allocated and freed here
 *
 */
static UFSRVResult *
_FenceCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	if (unlikely(IS_EMPTY(ufsrvcmd_ptr)) || unlikely(IS_EMPTY(ufsrvcmd_ptr->fencecommand)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: MISSING PARAMS", __func__, pthread_self(), sesn_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	MessageQueueBackend *mq_ptr				=	NULL;
	MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;
	FenceCommand 				*fcmd_ptr			=	ufsrvcmd_ptr->fencecommand;//just for diagnostics
	redisReply 					*redis_ptr		=	NULL;

	mq_ptr=sesn_ptr->msgqueue_backend;

	msgqueue_msg.wire_data		=	(DataMessage *)data;
	msgqueue_msg.origin				=	masterptr->serverid;
	msgqueue_msg.target_ufsrv	=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv=1;
	msgqueue_msg.ufsrv_req_id	=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id	=	1;
	msgqueue_msg.command_type	=	MSGCMD_FENCE;									msgqueue_msg.has_command_type	=	1;
	msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
  MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
  msgqueue_msg.has_ufsrvuid = 1;

	size_t 		packed_sz	=	message_queue_message__get_packed_size(&msgqueue_msg);
	uint8_t 	packed_msg[packed_sz];
	message_queue_message__pack(&msgqueue_msg, packed_msg);

	FenceCommand *fencecmd_ptr = ufsrvcmd_ptr->fencecommand;
	unsigned char command_buf[packed_sz + MBUF];
	StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																								&((IncomingMessageDescriptor){MSGCMD_FENCE, fencecmd_ptr->header->when, SESSION_USERID(sesn_ptr), fencecmd_ptr->fences[0]->fid, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																								0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', group_name:'%s', members_sz:'%lu', origin:'%d', uname:'%s'}: Publishing Fence intra-message...", __func__, pthread_self(), sesn_ptr, ufsrv_ptr->reqid, fcmd_ptr->fences[0]->fname, fcmd_ptr->fences[0]->n_members, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

	redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_FENCE_PUBLISH_INTRAMSG, packed_msg, packed_sz);

	if (IS_PRESENT(redis_ptr)) {
		if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) goto exit_free;

		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}
	else goto exit_error;

	exit_free:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', group_name:'%s', members_sz:'%lu', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, fcmd_ptr->fences[0]->fname, fcmd_ptr->fences[0]->n_members, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
	freeReplyObject(redis_ptr);

	exit_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', group_name:'%s', members_sz:'%lu', origin:'%d', uname:'%s'}: RDIS CONNECTION ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, fcmd_ptr->fences[0]->fname, fcmd_ptr->fences[0]->n_members, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

inline static unsigned long _GetTargetId (MessageCommand *msgcmd_ptr);
inline static unsigned long
_GetTargetId (MessageCommand *msgcmd_ptr)
{
  if (msgcmd_ptr->header->command == MESSAGE_COMMAND__COMMAND_TYPES__SAY) return   msgcmd_ptr->fences[0]->fid;
  if (msgcmd_ptr->header->command == MESSAGE_COMMAND__COMMAND_TYPES__INTRO) {
	  return UfsrvUidGetSequenceIdFromEncoded(msgcmd_ptr->intro->to);
  }

  return 0;
}

/**
 * @brief: forward a MessageCommand types to the ufsrv processing environment. This is designed to work with ephemeral Sessions, e not
 * not serviced by a io worker thread and therefore my not be connected to the end-client
 *
 * @param sesn_ptr: this session is not connected to the end user
 *
 * @dynamic_memory: redis reply is allocated and freed here
 *
 */
static UFSRVResult *
_MessageCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	MessageCommand *msgcmd_ptr = ufsrvcmd_ptr->msgcommand;

	if (msgcmd_ptr->header->command == MESSAGE_COMMAND__COMMAND_TYPES__SAY && (IS_EMPTY(msgcmd_ptr->fences) || IS_EMPTY(msgcmd_ptr->fences[0])) ) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', origin:'%d', cid:'%lu'}: ERROR: MSGCOMMAND (SAY) HAS NULL FENCE DEFINED", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_ID(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	} else if (msgcmd_ptr->header->command == MESSAGE_COMMAND__COMMAND_TYPES__INTRO && (IS_EMPTY(msgcmd_ptr->intro) || !IS_STR_LOADED(msgcmd_ptr->intro->to)) ) {
      syslog(LOG_DEBUG,
             "%s {pid:'%lu', o:'%p', origin:'%d', cid:'%lu'}: ERROR: MSGCOMMAND (INTRO) HAS NULL TARGET USER DEFINED", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_ID(sesn_ptr));
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
    }

	redisReply			*redis_ptr		= NULL;
	MessageQueueBackend	*mq_ptr		= NULL;

	mq_ptr = sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.wire_data						=	(DataMessage *)data;
		msgqueue_msg.origin							=	masterptr->serverid;
		msgqueue_msg.target_ufsrv					=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv=1;
		msgqueue_msg.geogroup_id					=	ufsrv_ptr->ufsrv_geogroup; 		msgqueue_msg.has_geogroup_id=1;
		msgqueue_msg.ufsrv_req_id					=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id=1;
		msgqueue_msg.command_type					=	MSGCMD_MESSAGE;								msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

		size_t 	packed_sz		=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned long target_id = _GetTargetId(msgcmd_ptr);
		unsigned char command_buf[packed_sz + MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_MESSAGE, msgcmd_ptr->header->when, SESSION_USERID(sesn_ptr), target_id, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', target_id:'%lu', origin:'%d', cid:'%lu'}: Publishing Message intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, target_id, masterptr->serverid, SESSION_ID(sesn_ptr));
#endif

		redis_ptr = (*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_MSG " %b", packed_msg, packed_sz);

		if (IS_PRESENT(redis_ptr)) {
			if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', target_id:'%lu', origin:'%d', cid:'%lu', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, target_id, masterptr->serverid, SESSION_ID(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

/**
 * 	@brief:
 *
 * 	@param sesn_ptr: non connected message loaded in ephemeral mode
 */
static UFSRVResult *
_SessionCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	redisReply					*redis_ptr	= NULL;
	MessageQueueBackend	*mq_ptr			= NULL;

	SessionMessage *sesncmd_ptr=(SessionMessage *)data;

	mq_ptr=sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg		=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.session								=	(SessionMessage *)data;
		msgqueue_msg.origin									=	masterptr->serverid;
		msgqueue_msg.target_ufsrv						=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv=1;
		msgqueue_msg.ufsrv_req_id						=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id=1;
		msgqueue_msg.command_type						=	MSGCMD_SESSION;								msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics		=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA_WITH_INTER_SEMANTICS; msgqueue_msg.has_broadcast_semantics	=1;

		size_t packed_sz										=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned char command_buf[packed_sz+MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_SESSION, sesncmd_ptr->header->when, SESSION_USERID(sesn_ptr), sesncmd_ptr->header->cid, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s'}: Publishing intra-Session message...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

		redis_ptr=(*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_SESSION " %b", packed_msg, packed_sz);

		if (redis_ptr)
		{
			if (unlikely((redis_ptr->type==REDIS_REPLY_ERROR)))
			{
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

/**
 * 	@brief:
 */
static UFSRVResult *
_UserCommandIntraMarshal(Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	UserCommand 		*usercmd_ptr		=	ufsrvcmd_ptr->usercommand;
	redisReply			*redis_ptr		= NULL;
	MessageQueueBackend	*mq_ptr		= NULL;

	mq_ptr=sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.wire_data						=	(DataMessage *)data;
		msgqueue_msg.origin								=	masterptr->serverid;
		msgqueue_msg.target_ufsrv					=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv=1;
		msgqueue_msg.geogroup_id					=	ufsrv_ptr->ufsrv_geogroup; 		msgqueue_msg.has_geogroup_id=1;
		msgqueue_msg.ufsrv_req_id					=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id=1;
		msgqueue_msg.command_type					=	MSGCMD_USER;									msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

		size_t 	packed_sz		=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned char command_buf[packed_sz + MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_USER, usercmd_ptr->header->when, SESSION_USERID(sesn_ptr), 0, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', origin:'%d', uname:'%s'}: Publishing User intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

		redis_ptr = (*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_USER " %b", packed_msg, packed_sz);

		if (redis_ptr) {
			if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief:
 */
static UFSRVResult *
_CallCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	CallCommand 		*callcmd_ptr		=	ufsrvcmd_ptr->callcommand;
	redisReply			*redis_ptr		= NULL;
	MessageQueueBackend	*mq_ptr		= NULL;

	mq_ptr=sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.wire_data						=	(DataMessage *)data;
		msgqueue_msg.origin								=	masterptr->serverid;
		msgqueue_msg.target_ufsrv					=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv=1;
		msgqueue_msg.geogroup_id					=	ufsrv_ptr->ufsrv_geogroup; 		msgqueue_msg.has_geogroup_id=1;
		msgqueue_msg.ufsrv_req_id					=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id=1;
		msgqueue_msg.command_type					=	MSGCMD_CALL;									msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

		size_t 	packed_sz		=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned char command_buf[packed_sz+MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_CALL, callcmd_ptr->header->when, SESSION_USERID(sesn_ptr), 0, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', origin:'%d', uname:'%s'}: Publishing CallCommand intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

		redis_ptr=(*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_CALL " %b", packed_msg, packed_sz);

		if (redis_ptr) {
			if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief:
 */
static UFSRVResult *
_ReceiptCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	ReceiptCommand 		*rectcmd_ptr		=	ufsrvcmd_ptr->receiptcommand;
	redisReply			*redis_ptr		= NULL;
	MessageQueueBackend	*mq_ptr		= NULL;

	mq_ptr=sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.wire_data						=	(DataMessage *)data;
		msgqueue_msg.origin								=	masterptr->serverid;
		msgqueue_msg.target_ufsrv					=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv	=	1;
		msgqueue_msg.geogroup_id					=	ufsrv_ptr->ufsrv_geogroup; 		msgqueue_msg.has_geogroup_id	=	1;
		msgqueue_msg.ufsrv_req_id					=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id	=	1;
		msgqueue_msg.command_type					=	MSGCMD_RECEIPT;								msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

		size_t 	packed_sz		=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned char command_buf[packed_sz+MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_RECEIPT, rectcmd_ptr->header->when, SESSION_USERID(sesn_ptr), 0, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', origin:'%d', uname:'%s'}: Publishing ReceiptCommand intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

		redis_ptr = (*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_RECEIPT " %b", packed_msg, packed_sz);

		if (redis_ptr) {
			if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

static UFSRVResult *
_LocationCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded) {
  LocationCommand *location_cmd_ptr = ufsrvcmd_ptr->locationcommand;
  redisReply *redis_ptr = NULL;
  MessageQueueBackend *mq_ptr = NULL;

  mq_ptr = sesn_ptr->msgqueue_backend;

  {
    MessageQueueMessage msgqueue_msg = MESSAGE_QUEUE_MESSAGE__INIT;

    msgqueue_msg.wire_data = (DataMessage *) data;
    msgqueue_msg.origin = masterptr->serverid;
    msgqueue_msg.target_ufsrv = ufsrv_ptr->serverid_by_user;
    msgqueue_msg.has_target_ufsrv = 1;
    msgqueue_msg.geogroup_id = ufsrv_ptr->ufsrv_geogroup;
    msgqueue_msg.has_geogroup_id = 1;
    msgqueue_msg.ufsrv_req_id = ufsrv_ptr->reqid;
    msgqueue_msg.has_ufsrv_req_id = 1;
    msgqueue_msg.command_type = MSGCMD_SYNC;
    msgqueue_msg.has_command_type = 1;
    msgqueue_msg.broadcast_semantics = MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA;
    msgqueue_msg.has_broadcast_semantics = 1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

    size_t packed_sz = message_queue_message__get_packed_size(&msgqueue_msg);
    uint8_t packed_msg[packed_sz];
    message_queue_message__pack(&msgqueue_msg, packed_msg);

    unsigned char command_buf[packed_sz + MBUF];
    StoreStagedMessageCacheRecordForIntraCommand(sesn_ptr,
                                                 &((IncomingMessageDescriptor) {MSGCMD_LOCATION, location_cmd_ptr->header->when,
                                                                                SESSION_USERID(sesn_ptr), 0,
                                                                                (char *) packed_msg, packed_sz,
                                                                                ufsrv_ptr}),
                                                 0, command_buf);

#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', origin:'%d', uname:'%s'}: Publishing LocationCommand intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

    redis_ptr = (*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_LOC " %b", packed_msg, packed_sz);

    if (redis_ptr) {
      if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
        syslog(LOG_DEBUG,
               "%s {pid:'%lu', o:'%p', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE",
               __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
        freeReplyObject(redis_ptr);

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
      }

      freeReplyObject(redis_ptr);
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
    }
  }

  return_error:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief:
 */
static UFSRVResult *
_SyncCommandIntraMarshal (Session *sesn_ptr, UfsrvInstanceDescriptor *ufsrv_ptr, UfsrvCommandWire *ufsrvcmd_ptr, WireProtocolData *data, const unsigned char *rawmsg_b64encoded)
{
	SyncCommand 		*synccmd_ptr	=	ufsrvcmd_ptr->synccommand;
	redisReply			*redis_ptr		= NULL;
	MessageQueueBackend	*mq_ptr		= NULL;

	mq_ptr = sesn_ptr->msgqueue_backend;

	{
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;

		msgqueue_msg.wire_data						=	(DataMessage *)data;
		msgqueue_msg.origin								=	masterptr->serverid;
		msgqueue_msg.target_ufsrv					=	ufsrv_ptr->serverid_by_user; 	msgqueue_msg.has_target_ufsrv	=	1;
		msgqueue_msg.geogroup_id					=	ufsrv_ptr->ufsrv_geogroup; 		msgqueue_msg.has_geogroup_id	=	1;
		msgqueue_msg.ufsrv_req_id					=	ufsrv_ptr->reqid; 						msgqueue_msg.has_ufsrv_req_id	=	1;
		msgqueue_msg.command_type					=	MSGCMD_SYNC;									msgqueue_msg.has_command_type	=	1;
		msgqueue_msg.broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; msgqueue_msg.has_broadcast_semantics	=1;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;

		size_t 	packed_sz		=	message_queue_message__get_packed_size(&msgqueue_msg);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

		unsigned char command_buf[packed_sz+MBUF];
		StoreStagedMessageCacheRecordForIntraCommand (sesn_ptr,
																									&((IncomingMessageDescriptor){MSGCMD_SYNC, synccmd_ptr->header->when, SESSION_USERID(sesn_ptr), 0, (char *)packed_msg, packed_sz, ufsrv_ptr}),
																									0, command_buf);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', reqid:'%lu', origin:'%d', uname:'%s'}: Publishing SyncCommand intra-message...", __func__, pthread_self(), sesn_ptr, msgqueue_msg.ufsrv_req_id, masterptr->serverid, SESSION_USERNAME(sesn_ptr));
#endif

		redis_ptr=(*mq_ptr->send_command)(sesn_ptr, "PUBLISH " _INTRACOMMAND_SYNC " %b", packed_msg, packed_sz);

		if (redis_ptr)
		{
			if (unlikely((redis_ptr->type==REDIS_REPLY_ERROR)))
			{
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}