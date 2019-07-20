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


#ifndef INCLUDE_SESSION_SERVICE_H_
#define INCLUDE_SESSION_SERVICE_H_

#include <queue.h>
#include <users.h>
#include <session_type.h>
#include <session_service_type.h>
#include <ufsrvresult_type.h>
#include <json/json_object.h>

#define PROVIDER_SERVER 1
#define PROVIDER_CLIENT 2

enum {
	AM_SNEAK=1, AM_LOGIN,  AM_SIGNUP
  //SessionService.authentication_mode
 };

enum {
	//login verification msgs
	LVMSG_DUPLICATE_REJECT=1, LVMSG_MULTIPLELOGIN_REJECT, LVMSG_UNSUSPEND_SESSION, LVMSG_IDLE_SESSION_RESUME
};

 void DestructSessionService (InstanceHolderForSession *, unsigned);
 void ResetSessionService (InstanceHolderForSession *target, unsigned);
 unsigned CreateSessionService (Session *);


 //made static UFSRVResult *
 //ProcessUserInfo (Session *sesn_ptr, UFSRVResult *res_ptr_in);
 UFSRVResult *
 ProcessUserInfoUsingBackendSessionInstance (Session *sesn_ptr, UFSRVResult *res_ptr_in);

#define SESSION_SERVICE_USER(x) (x->sservice.user)
#define SESSION_SERVICE_USER_DETAILS(x) (x->sservice.user.user_details)

#define SESSION_SERVICE_USER_TRIP(x)\
		x->user_trips.counter++;\
		x->user_trips.last_trip_time=time(NULL)

#define SESSION_SERVICE_USER_FENCE_LIST(x)		(x->session_user_fence_list)//ok
#define SESSION_SERVICE_USER_MESSAGE_QUEUE(x)	(x->session_user_message_queue)//ok
#define SESSION_SERVICE_IN_LIST(x)				((SessionService *)(x->whatever))//ok use with ListEntry *


	 //user must cast this to appropriate type e.g. UserBackendAccessWordPress (UserBackendAccessWordPress *)
#define SESSION_BACKEND_ACCESS_DATA(x) (x->sservice.user_backend_access.user_backend_access_data)
#define SESSION_BACKEND_ACCESS_ROUTINES(x)	 (x->sservice.user_backend_access.user_backend_access_routines)

#define SESSION_SERVICE_BACKEND_ACCESS_DATA(x) (x->user_backend_access.user_backend_access_data)
#define SESSION_SERVICE_BACKEND_ACCESS_ROUTINES(x)	 (x->user_backend_access.user_backend_access_routines)

	#define qCURRENT_REQUEST(x) (x)->req_ptr
	#define qCURRENT_REQUEST_ID(x) (x)->req_ptr->re_id
	#define qCURRENT_REQUEST_STATUS(x) (x)->req_ptr->re_status
	#define	qREQUES_QUEUE_SIZE(x) (x->)req_que_history.Entries


#endif /* SRC_INCLUDE_SESSION_SERVICE_H_ */
