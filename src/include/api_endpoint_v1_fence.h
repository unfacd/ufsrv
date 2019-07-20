/*
 * api_endpoint_v1_fence.h
 *
 *  Created on: 27 Aug 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_API_ENDPOINT_V1_FENCE_H_
#define SRC_INCLUDE_API_ENDPOINT_V1_FENCE_H_


#include <session.h>



#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr)

API_ENDPOINT_V1(FENCE);
API_ENDPOINT_V1(FENCE_NEARBY);
API_ENDPOINT_V1(FENCE_SEARCH);

#endif /* SRC_INCLUDE_API_ENDPOINT_V1_FENCE_H_ */
