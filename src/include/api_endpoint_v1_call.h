/*
 * api_endpoint_v1_call.h
 *
 *  Created on: 28Mar.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_API_ENDPOINT_V1_CALL_H_
#define SRC_INCLUDE_API_ENDPOINT_V1_CALL_H_


#include <session.h>
#include <json/json.h>



#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr)

API_ENDPOINT_V1(CALL);
API_ENDPOINT_V1(CALL_TURN);

#endif /* SRC_INCLUDE_API_ENDPOINT_V1_CALL_H_ */
