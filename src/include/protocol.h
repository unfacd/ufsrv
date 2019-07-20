/*
 * protocols.h
 *
 *  Created on: 11 Mar 2015
 *      Author: ayman
 */

#ifndef INCLUDE_PROTOCOL_H_
#define INCLUDE_PROTOCOL_H_

#include <protocol_type.h>

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
