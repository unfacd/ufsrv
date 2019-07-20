/*
 * cdt_anderson_spinlock.h
 *
 *  Created on: 15 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_CDT_ANDERSON_SPINLOCK_H_
#define SRC_INCLUDE_CDT_ANDERSON_SPINLOCK_H_



/*
 * Largely based on ck's implementation but adapted for c11.
 *
 * Copyright 2010-2015 Samy Al Bahra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#ifndef SPINWAIT

#if (defined(__GNUC__) || defined(__clang__)) &&			\
    (defined(__amd64__) || defined(__x86_64__) ||			\
     defined(__i386__) || defined(__ia64__))
#define SPINWAIT() do { __asm __volatile("pause":::"memory"); } while (0)

/* Spinwait asm for MS compiler on i386/amd64. */
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#define SPINWAIT() do { __asm { __asm pause }; } while (0)

/* No pause instruction on other platforms/compilers. */
#define SPINWAIT() do { /* nothing */ } while (0)

#endif /* SPINWAIT platform selector. */

#endif /* SPINWAIT */

#define CACHELINE_SZ 64

struct spinlock_anderson_thread {
	atomic_uint locked;
	unsigned int position;
};
typedef struct spinlock_anderson_thread spinlock_anderson_thread_t;

struct spinlock_anderson {
	struct spinlock_anderson_thread *slots;
	unsigned int count;
	unsigned int wrap;
	unsigned int mask;
	char pad[CACHELINE_SZ - sizeof(unsigned int) * 3 - sizeof(void *)];
	atomic_uint next;
};
typedef struct spinlock_anderson spinlock_anderson_t;

inline static void
spinlock_anderson_init(struct spinlock_anderson *lock, struct spinlock_anderson_thread *slots, unsigned int count)
{
	unsigned int i;

	//slots[0].locked = false;
	atomic_init(&slots[0].locked, false);
	slots[0].position = 0;

	for (i = 1; i < count; i++)
	{
		//slots[i].locked = true;
		atomic_init(&slots[i].locked, true);
		slots[i].position = i;
	}

	lock->slots = slots;
	lock->count = count;
	lock->mask = count - 1;
	atomic_init(&lock->next, 0);
	//lock->next = 0;

	/*
	 * If the number of threads is not a power of two then compute
	 * appropriate wrap-around value in the case of next slot counter
	 * overflow.
	 */
	if (count & (count - 1))
		lock->wrap = (UINT_MAX % count) + 1;
	else
		lock->wrap = 0;

	//ck_pr_barrier();
	return;
}


inline static bool
spinlock_anderson_locked(struct spinlock_anderson *lock)
{
	unsigned int position;
	bool r;

	//position = ck_pr_load_uint(&lock->next) & lock->mask;
	position = atomic_load_explicit(&lock->next, memory_order_acquire)& lock->mask;

	//r = ck_pr_load_uint(&lock->slots[position].locked);
	r=atomic_load_explicit(&lock->slots[position].locked, memory_order_acquire);
	//ck_pr_fence_acquire();
	return r;
}


inline static void
spinlock_anderson_lock(struct spinlock_anderson *lock, struct spinlock_anderson_thread **slot)

{
	unsigned int position, next;
	unsigned int count = lock->count;

	/*
	 * If count is not a power of 2, then it is possible for an overflow
	 * to reallocate beginning slots to more than one thread. To avoid this
	 * use a compare-and-swap.
	 */
	if (lock->wrap != 0)
	{
		//position = ck_pr_load_uint(&lock->next);
		position=atomic_load_explicit(&lock->next, memory_order_acquire);

		do
		{
			if (position == UINT_MAX)
				next = lock->wrap;
			else
				next = position + 1;
		}
		while(atomic_compare_exchange_strong_explicit(&lock->next, &position, next, memory_order_release, memory_order_relaxed)==false);
		//while (ck_pr_cas_uint_value(&lock->next, position, next, &position) == false);

		position %= count;
	}
	else
	{
		//position = ck_pr_faa_uint(&lock->next, 1);//atomic fetch and add
		position=atomic_fetch_add_explicit(&lock->next, 1, memory_order_release);
		position &= lock->mask;
	}

	/* Serialize with respect to previous thread's store. */
	//ck_pr_fence_load();

	/*
	 * Spin until slot is marked as unlocked. First slot is initialized to
	 * false.
	 */
	//while (ck_pr_load_uint(&lock->slots[position].locked) == true)
	while (atomic_load_explicit(&lock->slots[position].locked, memory_order_acquire) == true)	SPINWAIT();

		//ck_pr_stall();

	/* Prepare slot for potential re-use by another thread. */
	//ck_pr_store_uint(&lock->slots[position].locked, true);
	atomic_store_explicit(&lock->slots[position].locked, true, memory_order_release);
	//ck_pr_fence_lock();

	*slot = lock->slots + position;

	return;
}

inline static void
spinlock_anderson_unlock(struct spinlock_anderson *lock, struct spinlock_anderson_thread *slot)

{
	unsigned int position;

	//ck_pr_fence_unlock();

	/* Mark next slot as available. */
	if (lock->wrap == 0)
		position = (slot->position + 1) & lock->mask;
	else
		position = (slot->position + 1) % lock->count;

	//ck_pr_store_uint(&lock->slots[position].locked, false);
	atomic_store_explicit(&lock->slots[position].locked, false, memory_order_release);
	return;
}

#endif /* SRC_INCLUDE_CDT_ANDERSON_SPINLOCK_H_ */
