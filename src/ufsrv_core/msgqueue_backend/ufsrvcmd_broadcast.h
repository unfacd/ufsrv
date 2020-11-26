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

#ifndef SRC_INCLUDE_UFSRVCMD_BROADCAST_H_
#define SRC_INCLUDE_UFSRVCMD_BROADCAST_H_

#include <main_types.h>
#include <session_type.h>
#include <ufsrv_core/fence/fence_event_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast_type.h>

#define REDIS_CMD_SESSION_PUBLISH_INTERMSG_P 	"PUBLISH UFSRV:SESSION %b"//for protobuf payload
#define REDIS_CMD_MSG_PUBLISH_INTERMSG_P 			"PUBLISH UFSRV:MSG %b"//for protobuf payload
#define REDIS_CMD_FENCE_PUBLISH_INTERMSG_P 		"PUBLISH UFSRV:FENCE %b"//for protobuf payload
#define REDIS_CMD_LOCATION_PUBLISH_INTERMSG_P "PUBLISH UFSRV:LOC %b"//for protobuf payload
#define REDIS_CMD_USER_PUBLISH_INTERMSG_P 		"PUBLISH UFSRV:USER %b"//for protobuf payload
#define REDIS_CMD_SYS_PUBLISH_INTERMSG_P 			"PUBLISH UFSRV:SYS %b"//for protobuf payload
#define REDIS_CMD_CALL_PUBLISH_INTERMSG_P 		"PUBLISH UFSRV:CALL %b"//for protobuf payload
#define REDIS_CMD_RECEIPT_PUBLISH_INTERMSG_P 	"PUBLISH UFSRV:RECEIPT %b"//for protobuf payload
#define REDIS_CMD_SYNC_PUBLISH_INTERMSG_P 		"PUBLISH UFSRV:SYNC %b"//for protobuf payload

//UFSRVResult *UfsrvInterBroadcastMessage (Session *sesn_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr, MessageQueueMessage *msgqqueue_ptr);
UFSRVResult *UfsrvInterBroadcastMessage (Session *sesn_ptr, MessageQueueMessage *msgqqueue_ptr, unsigned event_type);
UfsrvCommandBroadcast *GetBroadcastDescriptorByName (const char *topic);
UfsrvCommandBroadcast *GetBroadcastDescriptorByTopicId (enum UfsrvCmdTopicIds topic_id);
int WorkerThreadMsgQueueParserExecutor (MessageContextData *context_ptr);
MessageContextData *WorkerThreadMessageQueueParserExtractArg (MessageQueueMsgPayload *msgqueue_payload_ptr);
UFSRVResult *PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptr, CommandHeader *cmd_header_ptr, ClientContextData *context_ptr, UFSRVResult *res_ptr, int command, bool);

#endif /* SRC_INCLUDE_UFSRVCMD_BROADCAST_H_ */
