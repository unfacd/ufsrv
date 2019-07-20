/*
 * api_endpoint_v1_receipt.h
 *
 *  Created on: 19Oct.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_API_ENDPOINT_V1_RECEIPT_H_
#define SRC_INCLUDE_API_ENDPOINT_V1_RECEIPT_H_



#include <session.h>
#include <json/json.h>


#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr)

API_ENDPOINT_V1(RECEIPT);

#endif /* SRC_INCLUDE_API_ENDPOINT_V1_RECEIPT_H_ */
