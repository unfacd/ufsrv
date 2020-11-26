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

#ifndef SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_
#define SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_

#include <session_type.h>
#include <ufsrvresult_type.h>
#include <WebSocketMessage.pb-c.h>
#include <json/json.h>

typedef UFSRVResult * (*ClientCommandCallback) (InstanceContextForSession *, InstanceContextForSession *, WebSocketMessage *, struct json_object *, void *);

	struct UfsrvCommandResponse {
			UFSRVResult * (*callback) (InstanceContextForSession *, InstanceContextForSession *, WebSocketMessage *, struct json_object *, void *);
   };
	typedef struct UfsrvCommandResponse UfsrvCommandResponse;



#endif /* SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_ */
