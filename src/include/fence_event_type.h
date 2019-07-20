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

#ifndef INCLUDE_FENCE_EVENT_TYPE_H_
#define INCLUDE_FENCE_EVENT_TYPE_H_

#define EMPTY_EVENT NULL

typedef enum EnumEventType {
	EVENT_TYPE_FENCE,
	EVENT_TYPE_SESSION,
	EVENT_TYPE_USER,
	EVENT_TYPE_MESSAGE
} EnumEventType;

typedef struct FenceEvent {
	unsigned long eid;
	time_t	when;
	unsigned long session_id;
	unsigned long target_id;	//could be fence or another session
	unsigned event_type;
	void *event_payload; //msg
}	FenceEvent;

typedef struct FenceEvent UserEvent;
typedef struct FenceEvent MessageEvent;

typedef struct SessionEvent {
	unsigned long session_id;

}	SessionEvent;


//NOT IN USE
typedef struct UfsrvEvent {
	EnumEventType		event_type;
	unsigned 				instance_type; //type-specific type descriptor
	void 						*event_payload; //msg digest of event
	unsigned long 	eid;
	time_t					when;

	union {
		FenceEvent 		fence_event;
		SessionEvent	session_event;
		UserEvent     user_event;
		MessageEvent  message_event;
	} ufsrv_event;

}	UfsrvEvent;

//event type
enum {
	EVENT_TYPE_FENCE_CREATED=1, EVENT_TYPE_FENCE_DESTROYED, EVENT_TYPE_FENCE_USER_JOINED, EVENT_TYPE_FENCE_USER_PARTED, EVENT_TYPE_FENCE_MEMBERSHIP_REPAIRED,
	EVENT_TYPE_FENCE_USER_BOOTED, EVENT_TYPE_FENCE_USER_BLOCKED,  EVENT_TYPE_FENCE_USER_UNBLOCKED, EVENT_TYPE_FENCE_USER_INVITED,
	EVENT_TYPE_FENCE_USER_INVITED_JOINED, EVENT_TYPE_FENCE_USER_UNINVITED, EVENT_TYPE_FENCE_USER_LIST_CORRECTED, EVENT_TYPE_FENCE_USER_INVITEREJECTED, EVENT_TYPE_FENCE_USR_MSG, EVENT_TYPE_FENCE_STATE_SYNCED,
	EVENT_TYPE_FENCE_DNAME, EVENT_TYPE_FENCE_AVATAR,  EVENT_TYPE_FENCE_EXPIRY,EVENT_TYPE_FENCE_PERMISSION, EVENT_TYPE_FENCE_MAXMEMBERS,
	EVENT_TYPE_FENCE_JOIN_MODE, EVENT_TYPE_FENCE_PRIVACY_MODE, EVENT_TYPE_FENCE_DELIVERY_MODE, EVENT_TYPE_FENCE_LIST_SEMNATICS, EVENT_TYPE_FENCE_PERMISSION_ADDED, EVENT_TYPE_FENCE_PERMISSION_REMOVED,
	EVENT_TYPE_CALL_OFFER, EVENT_TYPE_CALL_ANSWER, EVENT_TYPE_CALL_BUSY, EVENT_TYPE_CALL_HANGUP,
	EVENT_TYPE_USER_MSG,
};


#endif /* INCLUDE_FENCE_EVENT_TYPE_H_ */
