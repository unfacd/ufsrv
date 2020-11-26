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

#ifndef SRC_INCLUDE_UFSRVCMD_BROADCAST_TYPE_H_
#define SRC_INCLUDE_UFSRVCMD_BROADCAST_TYPE_H_

#include <session_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/fence/fence_event_type.h>
#include <ufsrv_core/protocol/protocol_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue_type.h>

#define _INTERCOMMAND_SESSION		"UFSRV:SESSION"
#define _INTERCOMMAND_FENCE			"UFSRV:FENCE"
#define _INTERCOMMAND_MSG				"UFSRV:MSG"
#define _INTERCOMMAND_LOC				"UFSRV:LOC"
#define _INTERCOMMAND_USER			"UFSRV:USER"
#define _INTERCOMMAND_CALL			"UFSRV:CALL"
#define _INTERCOMMAND_RECEIPT		"UFSRV:RECEIPT"
#define _INTERCOMMAND_STATE	    "UFSRV:STATE"
#define _INTERCOMMAND_SYNC			"UFSRV:SYNC"
#define _INTERCOMMAND_SYS				"UFSRV:SYS"

//>>IMPORTANT INCREASE 'UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR' BELOW IF YOU MODIFY ENUMS

#define _INTRACOMMAND_MSG				"UFSRV:INTRA:MSG"
#define _INTRACOMMAND_FENCE			"UFSRV:INTRA:FENCE"
#define _INTRACOMMAND_USER			"UFSRV:INTRA:USER"
#define _INTRACOMMAND_SESSION		"UFSRV:INTRA:SESSION"
#define _INTRACOMMAND_LOC				"UFSRV:INTRA:LOC"
#define _INTRACOMMAND_CALL			"UFSRV:INTRA:CALL"
#define _INTRACOMMAND_RECEIPT		"UFSRV:INTRA:RECEIPT"
#define _INTRACOMMAND_STATE	    "UFSRV:INTRA:STATE"
#define _INTRACOMMAND_SYNC			"UFSRV:INTRA:SYNC"
#define _INTRACOMMAND_SYS				"UFSRV:INTRA:SYS"

#define REDIS_CMD_FENCE_PUBLISH_INTRAMSG 		"PUBLISH UFSRV:INTRA:FENCE %b"//for protobuf payload

//>>>>>>IMPORTNT SET THIS TO THE SIZE OF THE UFSRV_XXX SET. Used to add/substract index to find the corresponding INTRA->INTER or INTER->INTRA
#define UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR 	10

//both elements below are aligned index wise
//IMPORTANT TO KEEP THE SYMMETRY and order across the symmetry line

//IMPORTANT THIS SHOULD BE KEPT IN SYNC with 'enum UfsrvType' in protobuf schema file and  'enum UfsrvMsgCommandType' and the static
//command table defined in ufsrvcmd_broadcast.c

enum UfsrvCmdTopicIds {
	UFSRV_SESSION=0,
	UFSRV_FENCE,
	UFSRV_MSG,
	UFSRV_LOC,
	UFSRV_USER,
	UFSRV_CALL,
	UFSRV_RECEIPT,
	UFSRV_SYNC,
  UFSRV_STATE,
	UFSRV_SYS,

	//------------------// symmetry line

	UFSRV_INTRA_SESSION,
	UFSRV_INTRA_FENCE,
	UFSRV_INTRA_MSG,
	UFSRV_INTRA_LOC,
	UFSRV_INTRA_USER,
	UFSRV_INTRA_CALL,
	UFSRV_INTRA_RECEIPT,
	UFSRV_INTRA_SYNC,
  UFSRV_INTRA_STATE,
	UFSRV_INTRA_SYS,

	UFSRV_MAX_BROADCAST_ID
};

enum BroadcastSemantics {
	INTER_SEMANTICS												=	0, //pure INTER broadcast	receiver only modify local data model
	INTRA_SEMANTICS,													//pure INTRA broadcast	receiver expected to change backend data model
	INTRA_WITH_INTER_SEMANTICS,		//broadcast from outside server class Backend data model has already taken place, therefore treat message with INTER semantics
	INTER_WITH_INTRA_SEMANTICS
};

enum MessageQueueVerificationCodes {
	MSGQUE_SUCCESS					=	 0,
	MSGQUE_UNPACK_ERROR 		= -1,
	MSGQUE_EMPTY_WIREDATA		= -2,
	MSGQUE_EMPTY_COMMAND		=	-3,
	MSQQUE_SELFPUBLISHED		=	-4,
	MSGQUE_OTHER_TARGET			=	-5,
	MSGQUE_UNKNOWN_COMMAND	=	-6
};

enum MessageQueueVerificationCallFlags {
	MSGQUEFLAG_ALLOW_SELF_PUBLISH		=	 (0x1U<<1U),
	MSGQUEFLAG_ALLOW_OTHER_TARGET		=	 (0x1U<<2U),
	MSGQUEFLAG_CHECK_RECEPIENT_UID	=	 (0x1U<<3U),
	MSGQUEFLAG_CHECK_TARGETING_ONLY	=	 (0x1U<<4U),	//only check if the broadcast intended for the right target ie no self assignments
};

typedef UFSRVResult * (*BroadcastHandler)(MessageQueueMsgPayload *, MessageQueueMessage *, UFSRVResult *, unsigned long);
typedef UFSRVResult * (*BroadcastPreHandler)(WireProtocolData *, FenceSessionPair *fence_sesn_pair_ptr, UFSRVResult *res_ptr, int command);

typedef struct UfsrvCommandBroadcastOps {
	unsigned long verifier_callflags;
	int (*broadcast_handler)(MessageQueueMessage *, UFSRVResult *, unsigned long);
  BroadcastPreHandler broadcast_pre_handler;
	enum MessageQueueVerificationCodes  (*broadcast_verifier)(MessageQueueMsgPayload *, MessageQueueMessage 	**mqm_ptr_out, unsigned long);

} UfsrvCommandBroadcastOps;

typedef struct UfsrvCommandBroadcast {
	enum 				UfsrvCmdTopicIds 	topic_id;
	char 														*topic_name;

	UfsrvCommandBroadcastOps				ops;
} UfsrvCommandBroadcast;


#endif /* SRC_INCLUDE_UFSRVCMD_BROADCAST_TYPE_H_ */
