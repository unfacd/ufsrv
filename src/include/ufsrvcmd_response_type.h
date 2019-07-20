/*
 * ufsrvcmd_response_type.h
 *
 *  Created on: 21 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_
#define SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_

#include <session.h>
#include <ufsrvresult_type.h>
#include <WebSocketMessage.pb-c.h>
#include <json/json.h>


	struct UfsrvCommandResponse {
			UFSRVResult * (*callback) (Session *, Session *, WebSocketMessage *, struct json_object *, void *);
   };
	typedef struct UfsrvCommandResponse UfsrvCommandResponse;



#endif /* SRC_INCLUDE_UFSRVCMD_RESPONSE_TYPE_H_ */
