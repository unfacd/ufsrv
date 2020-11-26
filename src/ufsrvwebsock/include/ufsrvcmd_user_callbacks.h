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

#ifndef UFSRVCMD_USER_CALLBACKS_H
# define UFSRVCMD_USER_CALLBACKS_H

#include <recycler/instance_type.h>
#include <session_type.h>
#include <json/json.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>
#include <ufsrvresult_type.h>

#define UFSRV_USER_COMMAND(x) UFSRVResult * x (InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, WebSocketMessage *wsm_ptr_received, struct json_object *jobj, void *msgload)

//keep in sync with UfsrvCommand ufsrvcmd_client_bound_callbacks_array[] defined in ufsrvcmd_user_data.h
//keep in sync with enums defined in fsrvcmd_token_indexes.h
enum UFSRV_USER_COMMANDS_INDEXES {
	uOK_V1_IDX                    = 0,
	uACCOUNT_VERIFIED_V1_IDX      = 1,
	uSETACCOUNT_ATTRS_V1_IDX      = 2,
	uSYNC_V1_IDX                  = 3,
	uSTATE_V1_IDX                 = 4,
	uSETKEYS_V1_IDX               = 5,
	uGETKEYS_V1_IDX               = 6,
	uMSG_V1_IDX                   = 7,
	uLOCATION_V1_IDX              = 8,
	uFENCE_V1_IDX                 = 9,
	uSTATESYNC_V1_IDX             = 10,
	uNULL_IDX,
};

UFSRV_USER_COMMAND(uOK_V1);
UFSRV_USER_COMMAND(uACCOUNT_VERIFIED_V1);
UFSRV_USER_COMMAND(uSETACCOUNT_ATTRS_V1);
UFSRV_USER_COMMAND(uSYNC_V1);
UFSRV_USER_COMMAND(uSTATE_V1);
UFSRV_USER_COMMAND(uSETKEYS_V1);
UFSRV_USER_COMMAND(uGETKEYS_V1);
UFSRV_USER_COMMAND(uMSG_V1);
UFSRV_USER_COMMAND(uLOCATION_V1);
UFSRV_USER_COMMAND(uFENCE_V1);
UFSRV_USER_COMMAND(uSTATESYNC_V1);

#endif
