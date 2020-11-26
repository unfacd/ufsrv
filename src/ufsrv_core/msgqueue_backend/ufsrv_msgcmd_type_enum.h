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

#ifndef SRC_INCLUDE_UFSRV_MSGCMD_TYPE_ENUM_H_
#define SRC_INCLUDE_UFSRV_MSGCMD_TYPE_ENUM_H_


//IMPORTANT this derives from enum UfsrvCmdTopicIds'and must align with 'enum UfsrvType' in protobuffer schema file.
//Check ufsrvcmd_broadcast_type.h
typedef enum UfsrvMsgCommandType {
	MSGCMD_SESSION=0,
	MSGCMD_FENCE,
	MSGCMD_MESSAGE,
	MSGCMD_LOCATION,
	MSGCMD_USER,
	MSGCMD_CALL,
	MSGCMD_RECEIPT,
	MSGCMD_SYNC,
	MSGCMD_STATE
} UfsrvMsgCommandType;

#endif
