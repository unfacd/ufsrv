/*
 * ufsrvcmd_user_data.h
 *
 *  Created on: 1 Jun 2016
 *      Author: ayman
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
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uOK_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uACCOUNT_VERIFIED_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uSETACCOUNT_ATTRS_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uACCOUNT_GCM_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uACCOUNT_DIR_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uSETKEYS_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uGETKEYS_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uMSG_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uLOCATION_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uFENCE_V1	},
		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))uSTATESYNC_V1	},

		{(UFSRVResult * (*)(Session *, Session *, WebSocketMessage *, struct json_object *, void *))NULL				}, //make sure you don't fall into this idx
	};

#endif

