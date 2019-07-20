/*
 * api_endpoint_v1_user.h
 *
 *  Created on: 13Mar.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_API_ENDPOINT_V1_USER_H_
#define SRC_INCLUDE_API_ENDPOINT_V1_USER_H_



#include <session.h>
#include <json/json.h>



#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr)

API_ENDPOINT_V1(USER);
API_ENDPOINT_V1(USER_NETSTATE);
API_ENDPOINT_V1(USER_PRESENCE);

#endif /* SRC_INCLUDE_API_ENDPOINT_V1_USER_H_ */
