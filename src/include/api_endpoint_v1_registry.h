/*
 * api_endpoint_v1_registry.h
 *
 *  Created on: 18 Jul 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_API_ENDPOINT_V1_REGISTRY_H_
#define SRC_INCLUDE_API_ENDPOINT_V1_REGISTRY_H_


#include <session.h>
#include <json/json.h>



#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr)

API_ENDPOINT_V1(REGISTERY_USER);
API_ENDPOINT_V1(REGISTERY_USERID);



#endif /* SRC_INCLUDE_API_ENDPOINT_V1_REGISTRY_H_ */
