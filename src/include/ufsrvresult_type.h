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

#ifndef INCLUDE_UFSRVRESULT_TYPE_H_
#define INCLUDE_UFSRVRESULT_TYPE_H_

#define MAX_UFSRV_RESULT_MSG_SIZE MBUF

//result-code
enum {
	RESULT_TYPE_NOOP=0,
	RESULT_TYPE_IOERR, RESULT_TYPE_LOGICERR, RESULT_TYPE_NETERR, RESULT_TYPE_OSERR, RESULT_TYPE_LOCATIONERR,
	RESULT_TYPE_PROTOCOLERR,RESULT_TYPE_BACKENDERR,
	RESULT_TYPE_SUCCESS_NOOP, RESULT_TYPE_SUCCESS, RESULT_TYPE_SUCCESS_INFORM_USER,
	RESULT_TYPE_ERR,
	RESULT_TYPE_WARN_INFORM_USER, RESULT_TYPE_WARN_NOOP
};
//result_type
enum{
RESULT_CODE_NONE=0, RESCODE_SERVICED,

RESULT_CODE_USER_AUTHENTICATION, RESULT_CODE_USER_SIGNON, RESULT_CODE_USER_INITIALISED,	RESULT_CODE_USER_DUPLICATED,
RESULT_CODE_SESN_HARDSPENDED, RESULT_CODE_SESN_SOFTSPENDED, RESULT_CODE_SESN_INVALIDATED, RESCODE_SESSION_FENCE_INTEGRITY,
RESULT_CODE_USER_LOCATION,

RESCODE_USER_FENCE_FULL, RESCODE_USER_FENCE_PRIVATE,RESCODE_USER_FENCE_JOINED,RESCODE_USER_FENCE_MADE,
RESCODE_USER_FENCE_WRITEOFF, RESCODE_USER_FENCE_ALREADYIN, RESCODE_USER_FENCE_LOCATION,RESCODE_USER_FENCE_KEY,RESCODE_USER_FENCE_CANJOIN,
RESCODE_FENCE_EMPTY_INVITATION_LIST,RESCODE_FENCE_INVITATION_LIST, RESCODE_FENCE_FENCE_MEMBERSHIP, RESCODE_FENCE_LIST_SELFLOADED, RESCODE_FENCE_OWNERSHIP,
RESCODE_FENCE_EXISTS, RESCODE_FENCE_DOESNT_EXIST, RESCODE_FENCE_NAMING, RESCODE_FENCE_IDENTICAL, RESCODE_FENCE_INVITE_SIZE, RESCODE_FENCE_UKNOWN_TYPE,
RESCODE_FENCE_DATA_UPDATED, RESCODE_FENCE_EVENT_GENERATION, RESCODE_FENCE_EXPIRY, RESCODE_FENCE_DESTRUCTED, RESCODE_FENCE_PERMISSION,RESCODE_FENCE_PERMISSION_MEMBER,
RESCODE_FENCE_SESSION_INTEGRITY,RESCODE_FENCE_STATE, RESCODE_FENCE_INVALID_MAXMEMBERS, RESCODE_FENCE_INVALID_DELIVERY_MODE, RESCODE_FENCE_INVALID_JOIN_MODE,
	RESCODE_FENCE_MISSING_PARAM,

RESCODE_USERINFO_BAKENDERR,RESCODE_USERINFO_SUCCESS, RESCODE_USERINFO_UNKNOWN, RESCODE_ACCOUNT_DISABLED,RESCODE_USER_INVALID_UID,
RESCODE_USER_ONLINE, RESCODE_USER_BACKEND, RESCODE_USER_DUPLICATELOGIN, RESCODE_USER_SUSPENDED, RESCODE_USER_IDLE, RESCODE_USER_NOTONLINE,RESCODE_USER_BUDDIES,
RESCODE_USER_WRITEOFF,RESCODE_USER_TXTING,RESCODE_USER_NOT_IN_WRITEOFF,RESCODE_USER_LOGINREJECTED,RESCODE_USER_MIGRATED,RESCODE_USER_INSTATED,
RESCODE_USER_SESN_KILLED, RESCODE_USER_SESN_LOCAL, RESCODE_USER_AUTHCOOKIE, RESCODE_USER_RATELIMIT_EXCEEDED,
RESCODE_USER_SHARELIST_PRESENT, RESCODE_USER_PRIVACY_SETTING,

RESCODE_USERCMD_MISSING_PARAM, RESCODE_USERCMD_TOOLONG_PARAM,

RESCODE_IO_SUSPENDED, RESCODE_IO_USEMSG, RESCODE_IO_WOULDBLOCK, RESCODE_IO_CONNECTIONCLOSED,RESCODE_IO_MSGPARSED,RESCODE_IO_FRAMED,RESCODE_IO_MSGDISPATCHED,
RESCODE_IO_DECODED,RESCODE_IO_ENCODED, RESCODE_IO_MISSGINGFRAMEDATA,RESCODE_IO_PROTOUNPACKING, RESCODE_IO_PROTOPACKING, RESCODE_IO_SESSIONSTATE,
RESCODE_IO_POLL,RESCODE_IO_CONNECTED,RESCODE_IO_CACHEINVALIDATED,RESCODE_IO_NOTCACHED,
RESCODE_IO_POLLERROR,RESCODE_IO_FRAGMENTATION,RESCODE_IO_PROTOCOL_SHUTDOWN,RESCODE_IO_SOCKETQUEUE_CONSOLIDTED,

RESCODE_LOGIC_WOULDLOCK, RESCODE_LOGIC_CANTLOCK,RESCODE_LOGIC,RESCODE_LOGIC_NOCMND,RESCODE_LOGIC_EMPTY_RESOURCE,RESCODE_LOGIC_WITH_RESOURCE,
RESCODE_LOGIC_IDENTICAL_RESOURCE,

RESCODE_LOCATION_UNINIT, RESCODE_LOCATION_UNCHANGED, RESCODE_LOCATION_CHANGED,

RESCODE_PROTOCOL_NOSSL, RESCODE_PROTOCOL_WSHANDSHAKE, RESCODE_PROTOCOL_NOTSUPPORTED,RESCODE_PROTOCOL_DATA,

RESCODE_UFSRVGEOGROUP_DEFAULT,

RESCODE_UFSRV_INTERBROADCAST,

RESCODE_BACKEND_CONNECTION,RESCODE_BACKEND_DATA,RESCODE_BACKEND_DATA_EMPTYSET,RESCODE_BACKEND_DATA_PARTIALSET, RESCODE_BACKEND_DATA_EXISTINGSET,
RESCODE_BACKEND_DATA_SETCREATED,RESCODE_BACKEND_RESOURCE_LOCKED, RESCODE_BACKEND_RESOURCE_UPDATED, RESCODE_BACKEND_RESOURCE_NULL, RESCODE_BACKEND_RESOURCE_OWNER,
RESCODE_BACKEND_COMMAND, RESCODE_BACKEND_CONSTRAINT,

RESCODE_PROG_NULL_POINTER=1000,RESCODE_PROG_MEMORY_EXHAUSTED=1001, RESCODE_PROG_MISSING_PARAM=1002, RESCODE_PROG_HASHED=1003,RESCODE_PROG_LOCKED=1004,RESCODE_PROG_WONTLOCK=1005,
RESCODE_PROG_INCONSISTENT_STATE=1006, RESCODE_PROG_JSON_PARSER=1007,RESCODE_PROG_PROTOBUF_UNPACKER=1008, RESCODE_PROG_PROTOBUF_PACKER=1009, RESCODE_PROG_INCONSISTENT_DATA=1010,
RESCODE_PROG_LOCKED_THIS_THREAD=10011, RESCODE_PROG_RESOURCE_CACHED=10012
};


struct UFSRVResult {
	void *result_user_data;//generic carrier of objects
	//char result_msg[MAX_UFSRV_RESULT_MSG_SIZE];
	unsigned result_code;//enum category into array of return message carefully categorized
	//unsigned result_code_idx; //index within a category
	unsigned result_type;//enum
};

typedef struct UFSRVResult UFSRVResult;

static UFSRVResult _ErrorResultType = {
		.result_user_data=NULL,
		.result_code=RESCODE_PROG_NULL_POINTER,
		.result_type=RESULT_TYPE_ERR,
};
static UFSRVResult _SuccessResultType = {
		.result_user_data=NULL,
		.result_code=RESCODE_PROG_NULL_POINTER,
		.result_type=RESULT_TYPE_SUCCESS,
};
static UFSRVResult *const _ufsrv_result_generic_error = &_ErrorResultType;
static UFSRVResult *const _ufsrv_result_generic_success = &_SuccessResultType;

//expects w as UFSRVResult *
#define _RETURN_RESULT_RES(w,x, y, z)\
{\
	w->result_user_data=(void *)x;\
	w->result_type=y;\
	w->result_code=z;\
	return w;\
}

//all macros expect a pointer to SessionSesrvice
#define _RETURN_RESULT(w,x, y, z)\
{\
	w->result.result_user_data=(void *)x;\
	w->result.result_type=y;\
	w->result.result_code=z;\
	return (void *)&(w->result);\
}

#define __RETURN_RESULT(w,x, y, z)\
{\
	w.result.result_user_data=(void *)x;\
	w.result.result_type=y;\
	w.result.result_code=z;\
	return (void *)&(w.result);\
}


//TODO: delete this
//w is Session *
#define _RETURN_RESULT_SESN(w,x, y, z)\
{\
	w->sservice.result.result_user_data=(void *)x;\
	w->sservice.result.result_type=y;\
	w->sservice.result.result_code=z;\
	return (void *)&(w->sservice.result);\
}

#define SESSION_RETURN_RESULT(w,x, y, z)\
{\
	w->sservice.result.result_user_data=(void *)x;\
	w->sservice.result.result_type=y;\
	w->sservice.result.result_code=z;\
	return (void *)&(w->sservice.result);\
}

//Expects UFSRVResult *
#define _RESULT_TYPE_SUCCESS(x) (((x)->result_type==RESULT_TYPE_SUCCESS) || ((x)->result_type==RESULT_TYPE_SUCCESS_INFORM_USER) || ((x)->result_type==RESULT_TYPE_SUCCESS_NOOP))
#define _RESULT_TYPE_ERROR(x) (((x)->result_type==RESULT_TYPE_ERR) || ((x)->result_type==RESULT_TYPE_BACKENDERR) || ((x)->result_type==RESULT_TYPE_PROTOCOLERR) || ((x)->result_type==RESULT_TYPE_IOERR))
#define _RESULT_TYPE_WARNING(x) (((x)->result_type==RESULT_TYPE_WARN_NOOP) || ((x)->result_type==RESULT_TYPE_WARN_INFORM_USER))

#define _RESULT_CODE_EQUAL(x, y) ((x)->result_code==(y))
#define _RESULT_TYPE_EQUAL(x, y) ((x)->result_type==(y))
#define _RESULT_USERDATA(x) ((x)->result_user_data)
#define _RESULT_TYPE(x)	((x)->result_type)
#define _RESULT_CODE(x)	((x)->result_code)

//Session *
#define SESSION_RESULT_TYPE_SUCCESS(x) ((x->sservice.result.result_type==RESULT_TYPE_SUCCESS) || (x->sservice.result.result_type==RESULT_TYPE_SUCCESS_INFORM_USER) || (x->sservice.result.result_type==RESULT_TYPE_SUCCESS_NOOP))
#define SESSION_RESULT_TYPE_ERROR(x) ((x->sservice.result.result_type==RESULT_TYPE_ERR) || (x->sservice.result.result_type==RESULT_TYPE_BACKENDERR) || (x->sservice.result.result_type==RESULT_TYPE_PROTOCOLERR) || (x->sservice.result.result_type==RESULT_TYPE_IOERR))
#define SESSION_RESULT_TYPE_WARNING(x) ((x->sservice.result.result_type==RESULT_TYPE_WARN_NOOP) || (x->sservice.result.result_type==RESULT_TYPE_WARN_INFORM_USER))

#define SESSION_RESULT_CODE_EQUAL(x, y) (x->sservice.result.result_code==y)
#define SESSION_RESULT_TYPE_EQUAL(x, y) (x->sservice.result.result_type==y)
#define SESSION_RESULT_USERDATA(x) (x->sservice.result.result_user_data)

#define SESSION_RESULT_CODE(x) (x->sservice.result.result_code)
#define SESSION_RESULT_TYPE(x) (x->sservice.result.result_type)
#define SESSION_RESULT_USERDATA(x) (x->sservice.result.result_user_data)
//end Session *

#define RETURN_RESULT_NOOP(x)\
{\
	x->result.result_user_data=(void *)NULL;\
	x->result.result_type=RESULT_TYPE_NOOP;\
	x->result.result_code=RESULT_CODE_NONE;\
	return (void *)&(x->result);\
}


#endif /* SRC_INCLUDE_UFSRVRESULT_TYPE_H_ */
