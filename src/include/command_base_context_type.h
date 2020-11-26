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


#ifndef UFSRV_COMMAND_BASE_CONTEXT_TYPE_H
#define UFSRV_COMMAND_BASE_CONTEXT_TYPE_H

#include <session_type.h>
#include <ufsrv_core/fence/fence_event_type.h>

#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>

/**
 * @brief A common data context that applies to to any command handling operation. By convention, specialised commands
 * define their own data context, whilst including this as first member of their structure.
 */

typedef struct CommandBaseContext {
  DataMessage *data_msg_ptr_received;
  WebSocketMessage *wsm_ptr_received;
  UfsrvEvent *event_ptr;
  struct {
    InstanceContextForSession *ctx_ptr;
    bool  lock_state;
  } sesn_originator;
  ClientContextData *client_ctx_ptr; //placeholder for processor provided context data
} CommandBaseContext;

#define COMMAND_BASE_CONTEXT(x) ((CommandBaseContext *)(x))
#define CMDCTX_SESN_ORIGINATOR(x) ((x)->command_base_context.sesn_originator.ctx_ptr->sesn_ptr)
#define CMDCTX_SESN_INSTANCE_ORIGINATOR(x) ((x)->command_base_context.sesn_originator.ctx_ptr->instance_sesn_ptr)
#define CMDCTX_SESN_CTX_ORIGINATOR(x) ((x)->command_base_context.sesn_originator.ctx_ptr)
#define CMDCTX_SESN_LOCK_STATE_ORIGINATOR(x) ((x)->command_base_context.sesn_originator.lock_state)

#define CMDCTX_DATA_MESSAGE(x) ((x)->command_base_context.data_msg_ptr_received)
#define CMDCTX_WSM(x) ((x)->command_base_context.wsm_ptr_received)
#define CMDCTX_EVENT(x) ((x)->command_base_context.event_ptr)
#define CMDCTX_CLIENT_CTX_DATA(x) ((x)->command_base_context.client_ctx_ptr)

#endif //UFSRV_COMMAND_BASE_CONTEXT_TYPE_H
