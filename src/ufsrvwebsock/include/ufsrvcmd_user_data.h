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

#ifndef SRC_INCLUDE_UFSRVCMD_USER_DATA_H_
#define SRC_INCLUDE_UFSRVCMD_USER_DATA_H_

#include <ufsrvcmd_response_type.h>//includes necessary type definitions for function params below, as well as UfsrvCommand type def
#include <ufsrvcmd_user_callbacks.h>//function definitions

//commands issued from server-> client. caller will have idx. Used with 'MarshalCommand'
//keep in sync with enum UFSRV_USER_COMMANDS_INDEXES defined in ufsrvcmd_user_callbacks.h
//keep in sync with enums defined in fsrvcmd_token_indexes.h
static const UfsrvCommandResponse ufsrvcmd_client_bound_callbacks_array []=
	{
		{(ClientCommandCallback) uOK_V1	},
		{(ClientCommandCallback) uACCOUNT_VERIFIED_V1	},
		{(ClientCommandCallback) uSETACCOUNT_ATTRS_V1	},
		{(ClientCommandCallback) uSYNC_V1	},
		{(ClientCommandCallback) uSTATE_V1	},
		{(ClientCommandCallback) uSETKEYS_V1	},
		{(ClientCommandCallback) uGETKEYS_V1	},
		{(ClientCommandCallback) uMSG_V1	},
		{(ClientCommandCallback) uLOCATION_V1	},
		{(ClientCommandCallback) uFENCE_V1	},
		{(ClientCommandCallback) uSTATESYNC_V1	},

		{(ClientCommandCallback) NULL				}, //make sure you don't fall into this idx
	};

#endif

