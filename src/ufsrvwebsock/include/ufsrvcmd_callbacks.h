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

#ifndef UFSRVCMD_CALLBACKS_H
# define UFSRVCMD_CALLBACKS_H

#include <recycler/instance_type.h>
#include <ufsrv_core/protocol/protocol_type.h>
#include <session_type.h>
#include <json/json.h>
#include <WebSocketMessage.pb-c.h>

//IMPORTANT
//keep in sync with enum UFSRV_COMMANDS_INDEXES defined in ufsrvcmd_callbacks.h
//keep in sync with enums defined in fsrvcmd_token_indexes.h
//keep in synch with data table ufsrvcmd_data.h, which defines the size of the array and provide direct indexing
#define UFSRV_COMMAND(x) UFSRVResult * x (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr, WireProtocolData *dm_ptr)

	UFSRVResult * sNOT_USED_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);
	UFSRVResult * sKEEPALIVE_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//0
	UFSRVResult * sCALL_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//1
	UFSRVResult * sUSER_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//2
	UFSRVResult * sACCOUNT_GCM_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//3

	UFSRVResult * sACTIVITY_STATE_V1	(InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//4
	UFSRVResult * sSET_KEYS_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//5
	UFSRVResult * sGET_KEYS_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//6
	UFSRVResult * sMSG_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//7
	UFSRVResult * sLOCATION_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//8
	UFSRVResult * sFENCE_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//9
	UFSRVResult * sSTATESYNC_V1 (InstanceContextForSession *, WebSocketMessage *, WireProtocolData *);//10

#endif
