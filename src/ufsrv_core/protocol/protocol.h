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

#ifndef INCLUDE_PROTOCOL_H_
#define INCLUDE_PROTOCOL_H_

#include <ufsrv_core/protocol/protocol_type.h>

/*
TBA
 - each protocol defines a protocol-specific include file that includes
	function delerations. eg.g. protocol_websockets.h
 - this header file must be inluded in protocol_data.h to support
	function pointer definitions in the array
 - each protocol provide necessary calls back as per the definitions below
 - each protocol gets a slot in the statically defined array-of-structs 
	'static const ProtocolCallbacks ProtocolCallbackWebsockets []' defined in
	protocol_data.
 - You should not access 'ProtocolCallbackWebsockets' directly; rather, 
	use the pointer declared in protocol.c:
 - const  ProtocolCallbacks *const protocol_callbacks=ProtocolCallbackWebsockets
 - declare it extern and use that.
 - each protocol has a unique index defined in a set of enums in ufsrv.h
	websockets is 0
*/

void InitProtocols ();
Protocol *ProtocolGet (unsigned protocol_id);

#endif /* INCLUDE_PROTOCOLS_H_ */
