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

#ifndef UFSRV_MESSAGE_COMMAND_CONTROLLER_H
#define UFSRV_MESSAGE_COMMAND_CONTROLLER_H

#include <command_base_context_type.h>
#include <session_type.h>
#include <incoming_message_descriptor_type.h>
#include <command_controllers.h>

typedef struct MessageCommandContext {
  CommandBaseContext command_base_context;
  long fid;
  ParsedMessageDescriptor *msg_descriptor_ptr;
  struct {
    struct {
      InstanceContextForSession *ctx_sesn_ptr;
      bool lock_state;
    } sesn_target;
    InstanceContextForFence *ctx_f_ptr;
  } marshaller_context;
}	MessageCommandContext;

#define CMDCTX_MSG_TARGET_SESN(x) ((x)->marshaller_context.sesn_target)
#define CMDCTX_MSG_TARGET_SESN_INSTANCE(x) ((x)->marshaller_context.sesn_target.ctx_sesn_ptr->instance_sesn_ptr)
#define CMDCTX_MSG_TARGET_SESN_PTR(x) ((x)->marshaller_context.sesn_target.ctx_sesn_ptr->sesn_ptr)
#define CMDCTX_MSG_TARGET_SESN_LOCKED_STATE(x) ((x)->marshaller_context.sesn_target.ctx_sesn_ptr->is_locked)
#define CMDCTX_MSG_TARGET_SESN_LOCK_ALREADY_OWNED(x) ((x)->marshaller_context.sesn_target.ctx_sesn_ptr->lock_already_owned)
#define CMDCTX_MSG_FENCE_CTX(x) ((x)->marshaller_context.ctx_f_ptr)
#define CMDCTX_MSG_FENCE(x) ((x)->marshaller_context.ctx_f_ptr->f_ptr)
#define CMDCTX_MSG_FENCE_INSTANCE(x) ((x)->marshaller_context.ctx_f_ptr->instance_f_ptr)
#define CMDCTX_MSG_FENCE_LOCK_OWNED(x) ((x)->marshaller_context.ctx_f_ptr->lock_already_owned)
#define CMDCTX_MSG_FENCE_LOCKED_STATE(x) ((x)->marshaller_context.ctx_f_ptr->is_locked)
#define CMDCTX_MSG_FENCE_LOCKED_STATE_SET_TRUE(x) ((x)->marshaller_context.ctx_f_ptr->is_locked=true)
#define CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(x) ((x)->marshaller_context.ctx_f_ptr->is_locked=false)

UFSRVResult *CommandCallbackControllerMessageCommand (InstanceContextForSession *ctx_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, ParsedMessageDescriptor *);
UFSRVResult *IsUserAllowedToReportMessage (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);
UFSRVResult *IsUserAllowedToRequestGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);
UFSRVResult *IsUserAllowedToLinkGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);
UFSRVResult *IsUserAllowedToUnlinkGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);
UFSRVResult *IsUserAllowedToSendMessageEffect (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);
UFSRVResult *IsUserAllowedToSendMessageReaction (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags);

#endif //UFSRV_MESSAGE_COMMAND_CONTROLLER_H
