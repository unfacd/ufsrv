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

#ifndef SRC_INCLUDE_SESSION_SERVICE_TYPE_H_
#define SRC_INCLUDE_SESSION_SERVICE_TYPE_H_

#include <queue.h>
#include <list.h>
#include <user_type.h>
#include <ufsrvresult_type.h>
#include <trip_type.h>


//------------------------------------------------------------------------------
//to get address of containing Session object
	//container_of(ss_ptr, Session, session_service);
	struct SessionService {
			struct User user;
			List session_user_fence_list; //list of fences joined by the user
			List session_user_invited_fence_list;//fences for which the user has been invited

			UFSRVResult result;//generic return carrier mechanism
		};
	typedef struct SessionService SessionService;

#endif /* SRC_INCLUDE_SESSION_SERVICE_TYPE_H_ */
