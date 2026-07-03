/*
 * worker_stun_thread.h
 *
 *  Created on: 6 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_PROTO_STUN_INCLUDE_WORKER_STUN_THREAD_H_
#define SRC_PROTO_STUN_INCLUDE_WORKER_STUN_THREAD_H_

void *ThreadSfuConnectionListenerWorker(void *ptr);
int LaunchSessionsSfuDelegatorThread(void);
size_t UfsrvGetConnectionListenerWorkersSize(void);
int LaunchConnectionListenerThreads(UfsrvSessionsDelegator *sd_ptr);
void AddConnectionListenersPipeEndsToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr);

#endif /* SRC_PROTO_STUN_INCLUDE_WORKER_STUN_THREAD_H_ */
