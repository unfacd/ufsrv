/*
 * session_cachebackend.h
 *
 *  Created on: 16 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SESSION_CACHEBACKEND_H_
#define SRC_INCLUDE_SESSION_CACHEBACKEND_H_

#include <session_type.h>
#include <ufsrvresult_type.h>

//set a singular attribute for UID
#define REDIS_CMD_SESSION_SET_ATTRIBUTE "HSET UID:%lu %s %s"

//get a singular attribute
#define REDIS_CMD_SESSION_GET_ATTRIBUTE "HGET UID:%lu %s"


UFSRVResult *CacheBackendSetSessionAttribute (Session *sesn_ptr, unsigned long session_id, const char *attribute_name, const char *attribute_value);
UFSRVResult *CacheBackendGetSessionAttribute (unsigned long user_id, const char *attribute);


#endif /* SRC_INCLUDE_SESSION_CACHEBACKEND_H_ */
