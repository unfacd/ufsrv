/*
 * protocol_type.h
 *
 *  Created on: 30 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PROTOCOL_TYPE_H_
#define SRC_INCLUDE_PROTOCOL_TYPE_H_

#include <session.h>
#include <socket_type.h>
#include <ufsrvresult_type.h>

//fake type
typedef struct ProtocolTypeData ProtcolTypeData;
typedef struct Protocol Protocol;

//just a dummy type for readability
typedef void WireProtocolData;
#define _WIRE_PROTOCOL_DATA(x) ((WireProtocolData *)x)

//lifecycle callbacks per protocol type
struct ProtocolCallbacks {
	UFSRVResult * (*protocol_init_callback)(Protocol *);//called once at program startup per protocol type
	UFSRVResult *	(*config_callback)(ClientContextData *);//called at nit time to process config file entries
	UFSRVResult * (*init_listener_callback)(void);
	UFSRVResult * (*init_workers_delegator_callback)(void);
	UFSRVResult * (*main_listener_callback)(Socket *, ClientContextData *);
	UFSRVResult * (*session_init_callback)(struct Session *, unsigned);//called each time a new session is initiated
	UFSRVResult * (*session_reset_callback)(struct Session *, unsigned);//called each time a new session is reset flag is set for for recycling
	UFSRVResult * (*handshake_callback)(struct Session *, SocketMessage *, unsigned, int **);
	UFSRVResult * (*post_handshake_callback)(struct Session *, SocketMessage *, unsigned);
	UFSRVResult * (*msg_callback)(struct Session *, SocketMessage *, unsigned, size_t);//incoming
	UFSRVResult * (*msg_out_callback)(struct Session *, SocketMessage *, unsigned, size_t);//outgoing
	UFSRVResult * (*msg_decode_callback)(struct Session *, SocketMessage *, unsigned);
	UFSRVResult * (*msg_encode_callback)(struct Session *, SocketMessage *, unsigned);
	UFSRVResult * (*service_timeout_callback)(struct Session *, time_t, unsigned long); //session idled
	UFSRVResult * (*error_callback)(struct Session *, unsigned);
	UFSRVResult * (*recycler_error_callback)(struct Session *, unsigned);
	UFSRVResult * (*close_callback)(struct Session *);
	UFSRVResult * (*msgqueue_topics_callback)(UFSRVResult *);//supply msg queue topcs to subscribe to
 };
typedef struct ProtocolCallbacks ProtocolCallbacks;

struct ProtocolControls {
	unsigned read_blocked_session 		:1;//main loop can concurrent-read into incoming buffer by non lock-owner if session is locked
	unsigned read_inservice_session 	:1;//main loop can concurrent-read into incoming buffer by lock-owner if session is in-service
	unsigned retain_session_on_error	:1;//when I/O error occurs, dosn't destroy session straight away retain it for system default retention value before sending to recycler
	unsigned abort_on_ioerror					:1;//when session encounters IO error in main loop immediately suspend and dont process saved buffers
	unsigned client_of_recyler				:1;//protocol has type(s) managed by the type recycler
	unsigned cloudmsg_on_ioderror			:1;//protocol support notifications via cloud messaging if direct link was broken
	unsigned pub_session_transitions	:1;//publish session state transitions (created, suspended, signed off etc..)
	unsigned msgqueue_subscriber			:1;//subscribe to mesgbus for INTER/INTRA publishing across other connected instances
	unsigned mainlistener_semantics		:1;
};
typedef struct ProtocolControls ProtocolControls;


struct Protocol {
		const char *protocol_name;
		unsigned protocol_id;
		void * (*protocol_thread)(void *); //main processor thread the gets incoming requests
		ProtocolCallbacks protocol_callbacks;
		unsigned post_handshake;
		ProtocolTypeData *protocol_data; //protocol-type specific data structure as specified by user,  irrespective of connections
		ProtocolControls protocol_controls;
};


#define _ASSIGN_PROTOCOL_TYPE_DATA(x, y) \
	x->protocol_data=(ProtocolTypeData *)y

#define _GET_PROTO_WEBSOCKETS(x) \
	x=(protocols_registry_ptr+PROTOCOLID_WEBSOCKTES)

#define _GET_PROTO_HTTP(x) \
	x=(protocols_registry_ptr+PROTOCOLID_HTTP)

#define _GET_PROTOCOL_CALLBACKS_HTTP \
	(protocols_registry_ptr+PROTOCOLID_HTTP)->protocol_callback

//generic: user must supply an already indexed Protocol pointer
#define PROTO_PROTOCOL_NAME(x) 	(x->protocol_name)
#define PROTO_PROTOCOL_DATA(x) 	(x->protocol_data)
#define PROTO_PROTOCOL_THREAD(x) (x->protocol_thread)
#define PROTO_PROTOCOL_ID(x) 	(x->protocol_id)

#define PROTO_PROTOCOL_CLLBACKS(x) (x->protocol_callbacks)
#define PROTO_PROTOCOL_CLLBACKS_INIT(x) (x->protocol_callbacks.protocol_init_calback)
#define PROTO_PROTOCOL_CLLBACKS_CONFIG(x) (x->protocol_callbacks.config_callback)
#define PROTO_PROTOCOL_CLLBACKS_INIT_WORKERS_DELEGATOR(x) (x->protocol_callbacks.init_workers_delegator_callback)
#define PROTO_PROTOCOL_CLLBACKS_INIT_SESSION(x) (x->protocol_callbacks.session_init_calback)
#define PROTO_PROTOCOL_CLLBACKS_MAIN_LISTENER(x) (x->protocol_callbacks.main_listener_calback)
#define PROTO_PROTOCOL_CLLBACKS_RESET_SESSION(x) (x->protocol_callbacks.session_reset_callback)
#define PROTO_PROTOCOL_CLLBACKS_HANDSHAKE(x) (x->protocol_callbacks.handshake_callback)
#define PROTO_PROTOCOL_CLLBACKS_MSG(x) (x->protocol_callbacks.msg_calback)
#define PROTO_PROTOCOL_CLLBACKS_MSGOUT(x) (x->protocol_callbacks.msg_out_calback)
#define PROTO_PROTOCOL_CLLBACKS_SERVICE_TIMEOUT(x) (x->protocol_callbacks.service_timeout_calback)
#define PROTO_PROTOCOL_CLLBACKS_ERROR(x) (x->protocol_callbacks.error_calback)
#define PROTO_PROTOCOL_CLLBACKS_CLOSE(x) (x->protocol_callbacks.close_calback)
#define PROTO_PROTOCOL_CLLBACKS_MSGQUEUE_TOPICS(x) (x->protocol_callbacks.msgqueue_topics_callback)

// y is the protocol array index
#define _PROTOCOL_NAME(x, y) ((x+y))->protocol_name
#define _PROTOCOL_ID(x, y) ((x+y))->protocol_id
#define _PROTOCOL_DATA(x, y) ((x+y))->protocol_data
#define _PROTOCOL_THREAD(x, y) ((x+y))->protocol_thread
#define _PROTOCOL_CLLBACKS(x, y) ((x+y))->protocol_callbacks

//ProtocolControls
//if (_PROTOCOL_CTL_READ_BLOCKED_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
#define _PROTOCOL_CTL_READ_BLOCKED_SESSION(x, y) ((x+y))->protocol_controls.read_blocked_session
#define _PROTOCOL_CTL_READ_INSERVICE_SESSION(x, y) ((x+y))->protocol_controls.read_inservice_session
#define _PROTOCOL_CTL_RETAIN_SESSION_ON_ERROR(x, y) ((x+y))->protocol_controls.retain_session_on_error
#define _PROTOCOL_CTL_ABORT_ON_IOERROR(x, y)	((x+y))->protocol_controls.abort_on_ioerror
#define _PROTOCOL_CTL_CLIENT_OF_RECYCLER(x, y)	((x+y))->protocol_controls.client_of_recyler
#define _PROTOCOL_CTL_CLOUDMSG_ON_IOERROR(x, y)	((x+y))->protocol_controls.cloudmsg_on_ioderror
#define _PROTOCOL_CTL_PUB_SESSION_TRANSITIONS(x, y)	((x+y))->protocol_controls.pub_session_transitions
#define _PROTOCOL_CTL_MSGQUEUE_SUSCRIBER(x, y)	((x+y))->protocol_controls.msgqueue_subscriber
#define _PROTOCOL_CTL_MAIN_LISTENER_SEMANTICS(x, y)	((x+y))->protocol_controls.mainlistener_semantics

//EXAMPLE TO ACCESS ID FROM Session *
//PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))

//typical invocation based on sesn_ptr:
//To check for presence of func pointer:
//if (_PROTOCOL_CLLBACKS_RESET_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
//
//To invoke:
//UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(protocols_registry_ptr,
//										PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
//										sesn_ptr_target, SESSION_RECYCLER);
//
#define _PROTOCOL_CLLBACKS_INIT(x, y) ((x+y))->protocol_callbacks.protocol_init_callback
#define _PROTOCOL_CLLBACKS_INIT_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.protocol_init_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_LISTENER_INIT(x, y) ((x+y))->protocol_callbacks.init_listener_callback
#define _PROTOCOL_CLLBACKS_LISTENER_INIT_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.init_listener_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_CONFIG(x, y) ((x+y))->protocol_callbacks.config_callback
#define _PROTOCOL_CLLBACKS_CONFIG_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.config_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_WORKERS_DELEGATOR_INIT(x, y) ((x+y))->protocol_callbacks.init_workers_delegator_callback
#define _PROTOCOL_CLLBACKS_WORKERS_DELEGATOR_INIT_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.init_workers_delegator_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_MAIN_LISTENER(x, y) ((x+y))->protocol_callbacks.main_listener_callback
#define _PROTOCOL_CLLBACKS_MAIN_LISTENER_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.main_listener_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_INIT_SESSION(x, y) ((x+y))->protocol_callbacks.session_init_callback
#define _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.session_init_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_RESET_SESSION(x, y) ((x+y))->protocol_callbacks.session_reset_callback
#define _PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(x, y, ...)	((x+y)->protocol_callbacks.session_reset_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_HANDSHAKE(x, y) ((x+y))->protocol_callbacks.handshake_callback
#define _PROTOCOL_CLLBACKS_HANDSHAKE_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.handshake_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_POST_HANDSHAKE(x, y) ((x+y))->protocol_callbacks.post_handshake_callback
#define _PROTOCOL_CLLBACKS_POST_HANDSHAKE_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.post_handshake_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_MSG(x, y) ((x+y))->protocol_callbacks.msg_callback
#define _PROTOCOL_CLLBACKS_MSG_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.msg_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_MSG_OUT(x, y) ((x+y))->protocol_callbacks.msg_out_callback
#define _PROTOCOL_CLLBACKS_MSG_OUT_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.msg_out_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_DECODE_MSG(x, y)	((x+y))->protocol_callbacks.msg_decode_callback
#define _PROTOCOL_CLLBACKS_DECODE_MSG_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.msg_decode_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_ENCODE_MSG(x, y)	((x+y))->protocol_callbacks.msg_encode_callback
#define _PROTOCOL_CLLBACKS_ENCODE_MSG_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.msg_encode_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_SERVICE_TIMEOUT(x, y) ((x+y))->protocol_callbacks.service_timeout_callback
#define _PROTOCOL_CLLBACKS_SERVICE_TIMEOUT_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.service_timeout_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_ERROR(x, y) ((x+y))->protocol_callbacks.error_callback
#define _PROTOCOL_CLLBACKS_ERROR_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.error_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_RECYCLER_ERROR(x, y) ((x+y))->protocol_callbacks.recycler_error_callback
#define _PROTOCOL_CLLBACKS_RECYCLER_ERROR_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.recycler_error_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_CLOSE(x, y) ((x+y))->protocol_callbacks.close_callback
#define _PROTOCOL_CLLBACKS_CLOSE_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.close_callback)(__VA_ARGS__)

#define _PROTOCOL_CLLBACKS_MSGQUEUE_TOPICS(x, y) ((x+y))->protocol_callbacks.msgqueue_topics_callback
#define _PROTOCOL_CLLBACKS_MSGQUEUE_TOPICS_INVOKE(x, y, ...) ((x+y)->protocol_callbacks.msgqueue_topics_callback)(__VA_ARGS__)


#endif /* SRC_INCLUDE_PROTOCOL_TYPE_H_ */
