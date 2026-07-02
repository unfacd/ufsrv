
#ifndef SRC_PROTO_STUN_INCLUDE_PROTOCOL_STUN_H_
#define SRC_PROTO_STUN_INCLUDE_PROTOCOL_STUN_H_

#include <ufsrvmsg_core/include/ufsrvresult_type.h>
#include <ufsrvmsg_core/include/session_type.h>
#include <ufsrvmsg_core/protocol/protocol_type.h>

UFSRVResult *proto_sfu_init_callback(Protocol *proto_ptr);
UFSRVResult *proto_sfu_init_session_callback(Session *sesn_ptr, unsigned callflags);
UFSRVResult *proto_sfu_init_listener(void);
UFSRVResult *proto_sfu_main_listener_callback(Socket *sock_ptr_listener, ClientContextData *context_ptr);
UFSRVResult *proto_sfu_reset_session_callback(Session *sesn_ptr, unsigned callflags);
UFSRVResult *proto_stun_hanshake_callback(InstanceHolder *, SocketMessage *sm_ptr, unsigned callflags, int **comeback);
UFSRVResult *proto_stun_post_hanshake_callback(InstanceHolder *);
UFSRVResult *proto_sfu_msg_callback(InstanceHolder *, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len);
UFSRVResult *proto_sfu_msg_out_callback(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len);
UFSRVResult *proto_sfu_service_timeout_callback(Session *sesn_ptr, time_t now, unsigned long call_flags);
UFSRVResult *proto_sfu_error_callback(Session *sesn_ptr, unsigned call_flags);
UFSRVResult *proto_sfu_recycler_error_callback(Session *sesn_ptr, unsigned call_flags);
UFSRVResult *proto_sfu_close_callback(Session *sesn_ptr);
UFSRVResult *proto_stun_msgqueue_topics_callback(UFSRVResult *res_ptr);
UFSRVResult *proto_sfu_generate_session_id_callback(UFSRVResult *res_ptr, ClientContextData *context_data);

#endif /* SRC_PROTO_STUN_INCLUDE_PROTOCOL_STUN_H_ */
