/*
 * ufsrv_msgcmd_type_enum.h
 *
 *  Created on: 8 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UFSRV_MSGCMD_TYPE_ENUM_H_
#define SRC_INCLUDE_UFSRV_MSGCMD_TYPE_ENUM_H_


//IMPORTANT this derives from enum UfsrvCmdTopicIds'and must align with 'enum UfsrvType' in protobuffer schema file.
//Check ufsrvcmd_broadcast_type.h
typedef enum UfsrvMsgCommandType{
	MSGCMD_SESSION=0,
	MSGCMD_FENCE,
	MSGCMD_MESSAGE,
	MSGCMD_LOCATION,
	MSGCMD_USER,
	MSGCMD_CALL,
	MSGCMD_RECEIPT,
	MSGCMD_SYNC,
	MSGCMD_SYSTEM
} UfsrvMsgCommandType;

#endif
