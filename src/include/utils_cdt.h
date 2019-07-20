/*
 * utils_cdt.h
 *
 *  Created on: 23 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UTILS_CDT_H_
#define SRC_INCLUDE_UTILS_CDT_H_

#include <utils_clock.h>
#include <utils_random.h>
#  if defined(__SSE__)
#    include <xmmintrin.h>
#  endif

//needs to be initialised with _pause_seeds=seed_rand();
unsigned long *pause_seeds;

#if !defined(likely)
#	define likely(x)       __builtin_expect((x),1)
#endif

#if !defined(unlikely)
#	define unlikely(x)     __builtin_expect((x),0)
#endif

#ifdef __sparc__
#  define PAUSE    asm volatile("rd    %%ccr, %%g0\n\t" \
				::: "memory")
#else
#  define PAUSE _mm_pause()
#endif

#if !defined(COMPILER_BARRIER)
#  define COMPILER_BARRIER() __asm volatile ("" ::: "memory")
#endif

#if !defined(COMPILER_NO_REORDER)
#  define COMPILER_NO_REORDER(exec)		\
  COMPILER_BARRIER();				\
  exec;						\
  COMPILER_BARRIER()
#endif


#if !defined(PREFETCHW)
#  if defined(__x86_64__)
#    define PREFETCHW(x)		     asm volatile("prefetchw %0" :: "m" (*(unsigned long *)x))
#  elif defined(__sparc__)
#    define PREFETCHW(x)
#  elif defined(XEON)
#    define PREFETCHW(x)
#  else
#    define PREFETCHW(x)
#  endif
#endif

#if !defined(PREFETCH)
#  if defined(__x86_64__)
#    define PREFETCH(x)		     asm volatile("prefetch %0" :: "m" (*(unsigned long *)x))
#  elif defined(__sparc__)
#    define PREFETCH(x)
#  elif defined(XEON)
#    define PREFETCH(x)
#  else
#    define PREFETCH(x)
#  endif
#endif


/**
 * 	@brief repetition
 */
static inline void
pause_rep(uint32_t num_reps)
{
	volatile uint32_t i;
	for (i = 0; i < num_reps; i++)
	{
		PAUSE;
	}
}

static inline void
nop_rep(uint32_t num_reps)
{
	uint32_t i;
	for (i = 0; i < num_reps; i++)
	{
		__asm volatile ("");
	}
}


static inline void
cdelay(ticks_t cycles)
{
	if (unlikely(cycles == 0))
	{
		return;
	}

	ticks_t __ts_end = GetTicks() + (ticks_t) cycles;
	while (GetTicks() < __ts_end);
}


/**
 * 	cycle puase
 */
static inline void
cpause(ticks_t cycles)
{
#if defined(XEON)
    cycles >>= 3;
    ticks_t i;
    for (i=0;i<cycles;i++) {
      _mm_pause();
    }
#else
    ticks_t i;
    for (i=0; i<cycles; i++) {
      __asm__ __volatile__("nop");
    }
#endif
}


static inline void
udelay(unsigned int micros)
{
	double __ts_end = wtime() + ((double) micros / 1000000);
	while (wtime() < __ts_end);
}


static const size_t pause_fixed = 16384;

 static inline void
 do_pause()
 {
   cpause((mrand(pause_seeds) % pause_fixed));
 }


 static const size_t pause_max   = 16384;
 static const size_t pause_base  = 512;
 static const size_t pause_min   = 512;

 static inline void
 do_pause_exp(size_t nf)
 {
   if (unlikely(nf > 32))
	 {
		 nf = 32;
	 }
   const size_t p = (pause_base << nf);
   const size_t pm = (p > pause_max) ? pause_max : p;
   const size_t tp = pause_min + (mrand(pause_seeds) % pm);
   cdelay(tp);
 }

#define DO_PAUSE_TYPE         0       // 0: fixed max pause
                                      // 1: exponentially increasing pause


#if DO_PAUSE_TYPE == 0
#define DO_PAUSE()            do_pause()
#define NUM_RETRIES()
#elif DO_PAUSE_TYPE == 1
#define DO_PAUSE()            do_pause_exp(__nr++);
#define NUM_RETRIES()         __attribute__((unused)) size_t __nr;
#else

#endif

#endif /* SRC_INCLUDE_UTILS_CDT_H_ */
