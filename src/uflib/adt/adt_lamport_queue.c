/**
 * Copyright (C) 2015-2020 unfacd works
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <standard_defs.h>
#include <standard_c_includes.h>
#include <stdatomic.h>
#include <uflib/adt/adt_lamport_queue.h>
/**
 * 	Classic single producer, single consumer FIFO queue a la Lamport https://hal.inria.fr/hal-00862450/document implemented with
 * 	c11 atomics.
 */

#if 0
typedef struct LamportQueue
{
    atomic_size_t front_;
    atomic_size_t back_;
    size_t	queue_sz;
    size_t cached_front_;
    size_t cached_back_;
    QueueClientData **payload;
} LamportQueue;
#endif

void LamportQueueInit(LocklessSpscQueue *queue, QueueClientData **payload, size_t queue_sz)
{
	atomic_init(&queue->front_, 0);
	atomic_init(&queue->back_, 0);
	atomic_init(&queue->leased, 0);

	queue->cached_front_ = queue->cached_back_ = 0;
	queue->queue_sz=queue_sz;

	if (IS_PRESENT(payload))	queue->payload=payload;
	else											queue->payload=calloc(queue_sz, sizeof(void *));
}

bool LamportQueuePush(LocklessSpscQueue *queue, QueueClientData *elem)
{
	size_t b, f;

	b = atomic_load_explicit(&queue->back_, memory_order_relaxed);
	f = queue->cached_front_;

	if ((b + 1) % queue->queue_sz == f)
	{
		queue->cached_front_ = f = atomic_load_explicit(&queue->front_, memory_order_acquire);
	}
	else
	{
		/* front can only increase since the last time we read it, which means we can only get more space to push into.
 If we still have space left from the last time we read, we don't have to read again. */
	}

	if ((b + 1) % queue->queue_sz == f)
	{
			return false;
	}
	else
	{ /* not full */ }

	//queue->data_[b] = elem;
	queue->payload[b]=elem;
	atomic_store_explicit(&queue->back_, (b + 1) % queue->queue_sz, memory_order_release);
	atomic_fetch_add_explicit(&(queue->leased), 1, memory_order_release);

	return true;
}

bool LamportQueuePop(LocklessSpscQueue *queue, QueueClientData **elem)
{
    size_t b, f;
    f = atomic_load_explicit(&queue->front_, memory_order_relaxed);
    b = queue->cached_back_;
    if (b == f)
    {
	    queue->cached_back_ = b = atomic_load_explicit(&queue->back_, memory_order_acquire);
    }
    else
    { /* back can only increase since the last time we read it, which means we can only get more items to pop from.
	 	 	 If we still have items left from the last time we read, we don't have to read again. */
		}
    if (b == f)
    {
        return false;
    }
    else
    { /* not empty */ }
    //*elem = queue->data_[f];
    *elem = queue->payload[f];
    atomic_store_explicit(&queue->front_, (f + 1) % queue->queue_sz, memory_order_release);
    atomic_fetch_sub_explicit(&(queue->leased), 1, memory_order_release);

    return true;
}

__pure size_t
LamportQueueLeasedSize (LocklessSpscQueue *queue)
{
	return atomic_load_explicit(&(queue->leased),  memory_order_acquire);
}

#if 0

#define T int
#define SIZE 64

typedef struct LamportQueue
{
    atomic_size_t front_;
    atomic_size_t back_;
    size_t	queue_sz;
    size_t cached_front_;
    size_t cached_back_;
    //ClientData **payload;
    T data_[SIZE];
} LamportQueue;

void* producer(void *p)
{
    struct LamportQueue *queue = (struct LamportQueue*)p;
    int i;
    for (i = 0; i < 100;)
    {
        if(LamportQueue_push(queue, 36)) ++i;
    }

    return 0;
}

void* consumer(void *p)
{
    struct LamportQueue *queue = (struct LamportQueue*)p;
    int i;
    for (i = 0; i < 100;)
    {
        int v;
        if(LamportQueue_pop(queue, &v))
	{
            ++i;
	    assert(v == 36);
        }
    }

    return 0;
}


int main()
{
    struct LamportQueue queue;
    LamportQueue_init(&queue, 100);
    pthread_t t[2];
    pthread_create(&t[0], 0, producer, &queue);
    pthread_create(&t[1], 0, consumer, &queue);
    pthread_join(t[1], 0);
    pthread_join(t[0], 0);
}
#endif


