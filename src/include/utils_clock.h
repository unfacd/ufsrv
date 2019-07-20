/*
 * utils_clock.h
 *
 *  Created on: 23 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UTILS_CLOCK_H_
#define SRC_INCLUDE_UTILS_CLOCK_H_


#include 	<stdint.h>
#include	<sys/time.h>

typedef uint64_t ticks_t;


#if defined(__i386__)
static inline ticks_t
GetTicks(void)
{
  ticks ret;

  __asm__ __volatile__("rdtsc" : "=A" (ret));
  return ret;
}
#elif defined(__x86_64__)
static inline ticks_t
 GetTicks(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#elif defined(__sparc__)
static inline ticks_t
GetTicks()
{
  ticks ret = 0;
  __asm__ __volatile__ ("rd %%tick, %0" : "=r" (ret) : "0" (ret));
  return ret;
}
#endif


//ticks_t _getticks_correction = 0;
static inline ticks_t
getticks_correction_calc()
{
#	define GETTICKS_CALC_REPS 1000000
  ticks_t t_dur = 0;
  ticks_t _getticks_correction = 0;
  uint32_t i;

  for (i = 0; i < GETTICKS_CALC_REPS; i++)
  {
    ticks_t t_start = GetTicks();
    ticks_t t_end = GetTicks();
    t_dur += t_end - t_start;
  }
  _getticks_correction = (ticks_t)(t_dur / (double) GETTICKS_CALC_REPS);

  return _getticks_correction;
}

static inline double
wtime(void)
{
	struct timeval t;

	gettimeofday(&t, NULL);

	return (double)t.tv_sec + ((double)t.tv_usec)/1000000.0;
}


static inline ticks_t
get_noop_duration()
{
#define NOOP_CALC_REPS 1000000
	ticks_t noop_dur = 0;
	uint32_t i;

	ticks_t corr = getticks_correction_calc();
	ticks_t start;
	ticks_t end;

	start = GetTicks();

	for (i=0; i<NOOP_CALC_REPS; i++)
	{
		__asm__ __volatile__("nop");
	}

	end = GetTicks();

	noop_dur = (ticks_t)((end-start-corr)/(double)NOOP_CALC_REPS);

	return noop_dur;
}

#endif /* SRC_INCLUDE_UTILS_CLOCK_H_ */
