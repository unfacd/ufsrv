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

#ifndef UFSRVCMD_DATA_H
# define UFSRVCMD_DATA_H

#include <ufsrvcmd_type.h>
#include <ufsrvcmd_callbacks.h>

/**
 *  ONLY TO BE INCLUDED IN ONE PLACE
 * //IMPORTANT
//keep in sync with enum UFSRV_COMMANDS_INDEXES defined in ufsrvcmd_callbacks.h
//keep in sync with enums defined in fsrvcmd_token_indexes.h
//keep in synch with data table ufsrvcmd_data.h, which defines the size of the array and provide direct indxing
 */

static const UfsrvCommand ufsrvmd_server_bound_callbacks_array []=
{
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sKEEPALIVE_V1				},//0
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sVERIFY_NEW_ACCOUNT_V1		},//1
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sSET_ACCOUNT_ATTRIBUTES_V1	},//2

	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sACCOUNT_GCM_V1	},//3
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sACCOUNT_DIR_V1	},//4
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sSET_KEYS_V1	},//5
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sGET_KEYS_V1	},//6
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sMSG_V1	},//7
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sLOCATION_V1	},//8
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sFENCE_V1	},//9
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))sSTATESYNC_V1	},//10
	{(UFSRVResult * (*)(Session *, WebSocketMessage *, struct json_object *))NULL						}, //don't fall into this idx
};

#endif
