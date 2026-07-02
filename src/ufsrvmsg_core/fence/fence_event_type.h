/**
 * Copyright (C) 2015-2021 unfacd works
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

#ifndef INCLUDE_FENCE_EVENT_TYPE_H_
#define INCLUDE_FENCE_EVENT_TYPE_H_

#include <uflib/ufsrvuid.h>
#include <ufsrvmsg_core/msgqueue_backend/ufsrv_msgcmd_type_enum.h>

#define EMPTY_EVENT NULL

typedef enum  UfsrvMsgCommandType EnumEventCommandType;

//event type
typedef enum EnumEventType {
  EVENT_TYPE_FENCE_CREATED=1, EVENT_TYPE_FENCE_DESTROYED, EVENT_TYPE_FENCE_USER_JOINED, EVENT_TYPE_FENCE_USER_PARTED, EVENT_TYPE_FENCE_MEMBERSHIP_REPAIRED,
  EVENT_TYPE_FENCE_USER_BOOTED, EVENT_TYPE_FENCE_USER_BLOCKED,  EVENT_TYPE_FENCE_USER_UNBLOCKED, EVENT_TYPE_FENCE_USER_INVITED,
  EVENT_TYPE_FENCE_USER_INVITED_JOINED, EVENT_TYPE_FENCE_USER_UNINVITED, EVENT_TYPE_FENCE_USER_LIST_CORRECTED, EVENT_TYPE_FENCE_USER_INVITEREJECTED, EVENT_TYPE_FENCE_USR_MSG, EVENT_TYPE_FENCE_USR_MSG_EFFECT,
  EVENT_TYPE_FENCE_DNAME, EVENT_TYPE_FENCE_DESCRIPTION, EVENT_TYPE_FENCE_AVATAR,  EVENT_TYPE_FENCE_EXPIRY,EVENT_TYPE_FENCE_PERMISSION, EVENT_TYPE_FENCE_MAXMEMBERS,
  EVENT_TYPE_FENCE_JOIN_MODE, EVENT_TYPE_FENCE_PRIVACY_MODE, EVENT_TYPE_FENCE_DELIVERY_MODE, EVENT_TYPE_FENCE_LIST_SEMNATICS, EVENT_TYPE_FENCE_PERMISSION_ADDED, EVENT_TYPE_FENCE_PERMISSION_REMOVED, EVENT_TYPE_FENCE_USERPREF,
  EVENT_TYPE_FENCE_JOIN_REQUEST_ADDED, EVENT_TYPE_FENCE_JOIN_REQUEST_REJECTED, EVENT_TYPE_FENCE_JOIN_REQUEST_REMOVED, EVENT_TYPE_FENCE_JOIN_REQUEST_ACCEPTED, EVENT_TYPE_LINKJOIN_ACCEPTED, EVENT_TYPE_LINKJOIN_REJECTED, EVENT_TYPE_LINKJOIN_JOINED, EVENT_TYPE_LINKJOIN_ADDED,

  EVENT_TYPE_CALL_OFFER = 100, EVENT_TYPE_CALL_ANSWER, EVENT_TYPE_CALL_BUSY, EVENT_TYPE_CALL_HANGUP,

  EVENT_TYPE_MSG = 200, EVENT_TYPE_MSG_REPORTED, EVENT_TYPE_MSG_REVOKED,

  EVENT_TYPE_USER_INTRO = 300,

  EVENT_TYPE_USER_PREF = 400, EVENT_TYPE_USER_PROFILE_SHARE, EVENT_TYPE_USER_NETSTATE_SHARE, EVENT_TYPE_USER_READ_RECEIPT,
  EVENT_TYPE_USER_BLOCK, EVENT_TYPE_USER_SHARE_CONTACT, EVENT_TYPE_USER_GUARDIAN_REQUEST, EVENT_TYPE_USER_GUARDIAN_LINK, EVENT_TYPE_USER_GUARDIAN_UNLINK, EVENT_TYPE_USER_BLOCKED_FENCE,

  EVENT_TYPE_MSG_REACTION = 500,

} EnumEventType;

//align with ReportedContentRecord in proto. Also used in events table status field.
enum EventStatus {
    EVENT_STATUS_UNDEFINED = 0,
    EVENT_STATUS_REPORTED = 1,
    EVENT_STATUS_REVOKED,
    EVENT_STATUS_UNREPORTED, //un-report previously reported
    EVENT_STATUS_ABORTED = 1000 ///> event was generated, but due to processing error event id is not operational
};

typedef struct FenceEvent {
  EnumEventType		      event_type;
  EnumEventCommandType	event_cmd_type;
  unsigned 				      instance_type; //type-specific type descriptor
  void                  *event_payload; //msg
	unsigned long         eid;//event_type/event_cmd_type specific eid (e.g. fence events counter or user's events counter. )
  unsigned long 	      gid;//ufsrv-unique id currently based on db insertion id in table 'events'
	time_t                when;
  UfsrvUid              *originator_ptr;
  unsigned              originator_device;
	unsigned long         session_id;
	unsigned long         ctx_id;	//could be a fence or another session

}	FenceEvent;

typedef struct FenceEvent UserEvent;
typedef struct FenceEvent MessageEvent;

typedef struct SessionEvent {
	unsigned long session_id;

}	SessionEvent;

typedef struct UfsrvEvent {
  EnumEventType         event_type;
	EnumEventCommandType  event_cmd_type;
	unsigned 				      instance_type; //type-specific type descriptor
	void 						      *event_payload; //msg digest of event
	unsigned long 	      eid; //event_type/event_cmd_type specific eid (e.g. fence events counter or user's events counter. )
  unsigned long 	      gid;//ufsrv-unique id currently based on db insertion id in table 'events'
	time_t					      when;
  UfsrvUid              *originator_ptr;
  unsigned              originator_device;
  unsigned long         session_id;
  unsigned long         ctx_id; //could be a fence, userid, or other context specific id
	union {
		FenceEvent 		fence_event;
		SessionEvent	session_event;
		UserEvent     user_event;
		MessageEvent  message_event;
	} ufsrv_event;

}	UfsrvEvent;

typedef struct RetrievedUfsrvEvent {
  enum EventStatus  status;
  unsigned long     userid_originator; ///< sequence id of UfsrvId
  UfsrvEvent        ufsrv_event;
}	RetrievedUfsrvEvent;

typedef struct RetrievedUfsrvEvent UfsrvEventDescriptor; //just convenient typing for clarity and signalling intent

#endif /* INCLUDE_FENCE_EVENT_TYPE_H_ */
