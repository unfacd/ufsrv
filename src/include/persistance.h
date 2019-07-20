/*
 * persistance.h
 *
 *  Created on: 24 Jul 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PERSISTANCE_H_
#define SRC_INCLUDE_PERSISTANCE_H_

#include <hiredis.h>
#include <persistance_type.h>
#include <session.h>
#include <redis.h>


unsigned DisconnectPersistanceBackend(Session *, int);//redisContext *c, int keep_fd);
PersistanceBackend *InitialisePersistanceBackend (PersistanceBackend *);
UserMessageCacheBackend *InitialiseCacheBackendUserMessage (PersistanceBackend *in_per_ptr);
UserMessageCacheBackend *InitialiseCacheBackendFence (PersistanceBackend *in_per_ptr);
void PrintPersistanceError (Session *sesn_ptr, char *user_str)__attribute__((unused));


#endif /* SRC_INCLUDE_PERSISTANCE_H_ */
