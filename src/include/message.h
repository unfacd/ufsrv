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

#ifndef INCLUDE_MESSAGE_H_
#define INCLUDE_MESSAGE_H_

#include <ufsrvresult_type.h>
#include <session_type.h>
#include <message_type.h>
#include <session_service.h>
#include <transmission_message_type.h>
#include <incoming_message_descriptor_type.h>
#include <guardian_record_descriptor.h>
#include <fence.h>

enum StoredMessageOptions {
	MSGOPT_GET_FIRST 			= (0x1<<1),
	MSGOPT_GET_LAST				= (0x1<<2),
	MSGOPT_GETALL					=	(0x1<<3),
	MSGOPT_GETNAMED				=	(0x1<<4),
	MSGOPT_REMOVE					= (0x1<<5),
	MSGOPT_REMOVENAMED		= (0x1<<6),
	MSGOPT_GET_REM_FIRST	=	((0x1<<1)|(0x1<<5)),
	MSGOPT_GET_REM_LAST		=	((0x1<<2)|(0x1<<5)),
	MSGOPT_GET_REM_ALL		=	((0x1<<3)|(0x1<<5)),
};

//<uid> <uid>
#define REDIS_CMD_GUARDIAN_ADD "SADD GUARDIAN_FOR_%lu %lu"
#define REDIS_CMD_GUARDIAN_REM 			"SREM GUARDIAN_FOR_%lu %lu"
#define REDIS_CMD_FENCE_GUARDIAN_MEMBERS	"SMEMBERS GUARDIAN_FOR_%lu"
#define REDIS_CMD_FENCE_GUARDIAN_ISMEMBER	"SISMEMBER GUARDIAN_FOR_%lu %lu"

UFSRVResult *HandleStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name, enum StoredMessageOptions msg_opts);
UFSRVResult *StoreStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *,  unsigned long callflags, unsigned char *command_buf_in);
UFSRVResult *RemoveStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *, unsigned long call_flags);
UFSRVResult *GetStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr, const char *payload_name, enum StoredMessageOptions msg_opts);
UFSRVResult *GetRemoveStagedMessageCacheRecordForIntraCommand(Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name);
UFSRVResult *GetRemStagedMessageCacheRecordForIntraCommand (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr,  const char *payload_name, enum StoredMessageOptions);

UFSRVResult *AddMessageCacheRecordForUsers (Session *sesn_ptr, IncomingMessageDescriptor *msg_desc_ptr, UfsrvMsgCommandType msg_type, const unsigned char *b64encoded_rawmsg, unsigned long call_flags);
UFSRVResult *GetMessageFromCacheRecords (Session *sesn_ptr, unsigned long call_flags);
UFSRVResult *DeleteStagedMessageCacheRecordForUser (Session *sesn_ptr, TransmissionMessage *, unsigned long userid);
UFSRVResult *GetStagedMessageCacheRecordsForUserInJson (Session *sesn_ptr, unsigned long userid);
UFSRVResult *StoreStagedMessageCacheRecordForUser (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned long userid);
UFSRVResult *GetStageMessageCacheBackendListSize (Session *sesn_ptr, unsigned long userid);

int DbBackendInsertMessageRecord (const ParsedMessageDescriptor *in_msg_ptr);
int DbBackendUpdateMessageStatus (unsigned long eid, unsigned  long uid_flagged_by, enum EventStatus status);

char *GenerateGuardianNonce (Session *sesn_ptr, const char *value);
unsigned long IsGuardianLinkNonceValid (const char *nonce, unsigned long value);
UFSRVResult *DbBackendInsertGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr, bool force_data);
UFSRVResult *DbBackendGetGuardianRecord (GuardianRecordDescriptor *descriptor_ptr);
UFSRVResult *DbBackendGetGuardianRecords (GuardianRecordDescriptor *descriptor_ptr_guardian, CollectionDescriptor *collection_ptr_out);
UFSRVResult *DbBackendGetGuardianRecordForOriginator (GuardianRecordDescriptor *descriptor_ptr);
UFSRVResult *DbBackendDeleteGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr);
UFSRVResult *CacheBackendAddGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr);
UFSRVResult *CacheBackendRemGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr);
UFSRVResult *CacheBackendGetGuardianRecord (const GuardianRecordDescriptor *descriptor_ptr);
bool IsUserGuardianFor (const GuardianRecordDescriptor *);

// MSGS_FOR:<%uid>
#define REDIS_CMD_INTRAMESSAGE_LIST_GETALL 				"ZRANGE STAGED_INTRAMSGS_%s_%d 0 -1"
#define REDIS_CMD_INTRAMESSAGE_LIST_GET_EARLIEST 	"ZRANGE STAGED_INTRAMSGS_%s_%d 0 0"
#define REDIS_CMD_INTRAMESSAGE_LIST_GET_LAST 			"ZRANGE STAGED_INTRAMSGS_%s_%d -1 -1"
#define REDIS_CMD_INTRAMESSAGE_LIST_GET_NAMED 		"ZRANGE STAGED_INTRAMSGS_%s_%d %s"
#define REDIS_CMD_INTRAMESSAGE_LIST_REM_EARLIEST	"ZREMRANGEBYRANK STAGED_INTRAMSGS_%s_%d 0 0"
#define REDIS_CMD_INTRAMESSAGE_LIST_REM_LAST			"ZREMRANGEBYRANK STAGED_INTRAMSGS_%s_%d -1 -1"
#define REDIS_CMD_INTRAMESSAGE_LIST_REM_ALL				"ZREMRANGEBYRANK STAGED_INTRAMSGS_%s_%d 0 -1"


//OLD  ZADD INTRAMSGS__class>_<geogroup> <%now> <type>:<%uid_from>:<%fid>:<rawb64msg>
//#define REDIS_CMD_INTRAMESSAGE_RECORD_ADD "ZADD STAGED_INTRAMSGS_%s_%d %lu %d:%lu:%lu:%s"

//ZADD INTRAMSGS_<%class>_<%geogroup> <%reqid> <%reqid>:<%type>:<raw binarymsg>
#define REDIS_CMD_INTRAMESSAGE_RECORD_ADD "ZADD STAGED_INTRAMSGS_%s_%d %lu %lu:%d:%b"

//ZADD MSGS_FOR:<%uid> <%now> <type>:<%fid:%uidfrom>:<rawb64msg>
//#define REDIS_CMD_INMESSAGE_RECORD_ADD "ZADD MSGS_FOR:%lu %lu %d:%lu:%lu:%s"
#define REDIS_CMD_INTRAMESSAGE_RECORD_REM	"ZREM STAGED_INTRAMSGS_%s_%d %s"

//<%uid> <%current unix time>
#define REDIS_CMD_INTRAMESSAGE_RECORDE_EXPIRE	"ZREMRANGEBYSCORE STAGED_INTRAMSGS_%s_%d 0 %lu"


//ZADD INMSGS:<%uid_to> <%now_inmillis> <%fid>:<eid>
#define REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_ADD 		"ZADD STAGED_OUTMSG_EVENTS:%lu %lu %lu:%lu"
#define REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_GETALL "ZRANGE STAGED_OUTMSG_EVENTS:%lu 0 -1"
#define REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_EXPIRE	"ZREMRANGEBYSCORE STAGED_OUTMSG_EVENTS:%lu 0 %lu"
#define REDIS_CMD_STAGED_OUTMSG_EVENT_RECORD_REM		"ZREM STAGED_OUTMSG_EVENTS:%lu %lu:%lu"
#define REDIS_CMD_STAGED_OUTMSG_EVENT_COUNT					"ZCARD STAGED_OUTMSG_EVENTS:%lu"

//"HSET STAGED_INMSGS:<%uid> %<fid>:%<eid> %<msg_sz>:%<msg>"
#define REDIS_CMD_STAGED_OUTMSG_MSG_COMMAND_HEADER "HDEL STAGED_OUTMSG:"
#define REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_GET "HGET STAGED_OUTMSG:%lu %s"//when we get the message willbe already formatted as <fid:eid>
#define REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_ADD "HSET STAGED_OUTMSG:%lu %lu:%lu %lu:%b"
#define REDIS_CMD_STAGED_OUTMSG_MSG_RECORD_DEL "HDEL STAGED_OUTMSG:%lu %lu:%lu"

//<%uid> <%identifier> <%ttl time in socends>
//set processing lock
#define REDIS_CMD_STAGEDINMSG_PLOCK				"SET STAGED_INMSGS:PL:%lu %s NX EX %lu"
//<%sha1id>  <%uid> 1 is number of keys given as argument into the scrit
#define REDIS_CMD_STAGEDINMSG_DEL_PLOCK		"EVALSHA %s 1 STAGED_INMSGS:PL:%lu L"

#endif /* INCLUDE_MESSAGE_H_ */
