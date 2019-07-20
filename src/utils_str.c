/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <utils_str.h>


/**
 * @brief A convenient front end that returns pointer to user allocated buffer upon string formatting.
 * Check it's usage with the macro STRINGIFY_PARAMETER. Also check mdsprintf().
 * @param user_allocated_buffer should be large enough for all params on the call
 * @param format printf-like
 * @return
 */
__attribute__ ((format (printf, 2, 3))) char *
sprintf_provided_buffer (char *user_allocated_buffer, char *format, ...)
{
  if (IS_EMPTY(user_allocated_buffer)) return NULL;

  va_list args;
  va_start(args, format);
  vsprintf(user_allocated_buffer, format, args);
  va_end(args);

  return user_allocated_buffer;
}

unsigned digits_count (uint64_t number, unsigned base)
{
	unsigned digits = 1;
	uint64_t power  = 1;

	while (number/power >= base) {
		++digits;
		power *= base;
	}

	return digits;
}

/**
 * unsigned long to ascii
 * user must allocate char *ptr and pass it in, esnsuring it is of correct size
 * NOTE: Note very well tested for boundaries
 */
char *ultoa (unsigned long value, char *ptr, int base)
{
  unsigned long t = 0,
  							res = 0;
  unsigned long tmp = value;
  int count = 0;

  if (NULL == ptr) {
    return NULL;
  }

  if (tmp == 0) {
    count++;
  }

  while	(tmp > 0) {
    tmp = tmp/base;
    count++;
  }

  ptr += count;

  *ptr = '\0';

  do {
    res = value - base * (t = value / base);
    if (res < 10) {
      * -- ptr = '0' + res;
    } else if ((res >= 10) && (res < 16)) {
        * --ptr = 'A' - 10 + res;
    }
  } while ((value = t) != 0);

  return (ptr);

}


#define FLOAT_PRECISION 4

int itoa(char *ptr, uint32_t number)
{
	char *origin = ptr;
	int size;

	do {
		*ptr++ = '0' + (number % 10);
		number /= 10;
	} while (number);

	size = ptr - origin;
	ptr--;

	while (origin < ptr) {
		char t = *ptr;
		*ptr-- = *origin;
		*origin++ = t;
	}

	return size;
}


int ftoa(char *outbuf, float f)
{
	uint64_t mantissa, int_part, frac_part;
	int safe_shift;
	uint64_t safe_mask;
	short exp2;
	char *p;

	union {
		int L;
		float F;
	} x;

	x.F = f;
	p = outbuf;

	exp2 = (unsigned char)(x.L >> 23) - 127;
	mantissa = (x.L & 0xFFFFFF) | 0x800000;
	frac_part = 0;
	int_part = 0;

	if (x.L < 0) {
		*p++ = '-';
	}

	if (exp2 < -36) {
		*p++ = '0';
		goto END;
	}

	safe_shift = -(exp2 + 1);
	safe_mask = 0xFFFFFFFFFFFFFFFFULL >>(64 - 24 - safe_shift);

	if (exp2 >= 64) {
		int_part = ULONG_MAX;
	} else if (exp2 >= 23) {
		int_part = mantissa << (exp2 - 23);
	} else if (exp2 >= 0) {
		int_part = mantissa >> (23 - exp2);
		frac_part = (mantissa) & safe_mask;
	} else /* if (exp2 < 0) */ {
		frac_part = (mantissa & 0xFFFFFF);
	}

	if (int_part == 0) {
		*p++ = '0';
	} else {
		p += itoa(p, int_part);
	}

	if (frac_part != 0) {
		int m;

		*p++ = '.';

		for (m = 0; m < FLOAT_PRECISION; m++) {
			frac_part = (frac_part << 3) + (frac_part << 1);
			*p++ = (frac_part >> (24 + safe_shift)) + '0';
			frac_part &= safe_mask;
		}

		for (; p[-1] == '0'; --p) {}

		if (p[-1] == '.') {
			--p;
		}
	}

END:
	*p = 0;
	return p - outbuf;
}
