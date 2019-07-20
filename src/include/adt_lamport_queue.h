/*
 * adt_lamport_queue.h
 *
 *  Created on: 9 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_ADT_LAMPORT_QUEUE_H_
#define SRC_INCLUDE_ADT_LAMPORT_QUEUE_H_

typedef void QueueClientData;

typedef struct LamportQueue
{
    atomic_size_t front_;
    atomic_size_t back_;
    atomic_size_t	leased;
    size_t	queue_sz;
    size_t cached_front_;
    size_t cached_back_;
    QueueClientData **payload;
} LamportQueue;

typedef struct LamportQueue LocklessSpscQueue;

void LamportQueueInit(LocklessSpscQueue *queue, QueueClientData **payload, size_t queue_sz);
bool LamportQueuePush(LocklessSpscQueue *queue, QueueClientData *elem);
bool LamportQueuePop(LocklessSpscQueue *queue, QueueClientData **elem);
size_t LamportQueueLeasedSize (LocklessSpscQueue *queue);


#endif /* SRC_INCLUDE_ADT_LAMPORT_QUEUE_H_ */
