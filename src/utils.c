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
#include <utils_crypto.h>
#include <sys/stat.h>

//http://www.shieldadvanced.com/Blog/uncategorized/validate-email-address-in-c/
//https://stackoverflow.com/questions/42939688/phone-number-validation-in-c
bool
IsEmailAddressValid (const char *EM_Addr)
{
  int count = 0;
  int i = 0;
//  char conv_buf[MAX_EMAIL_NAME];
  char *conv_buf = strndupa(EM_Addr, CONFIG_EMAIL_ADDRESS_SZ_MAX);
  char *c, *domain;
  char *special_chars = "()<>@,;:\"[]";

/* The input is in EBCDIC so convert to ASCII first */
//  strcpy(conv_buf,EM_Addr);
//  EtoA(conv_buf);
///* convert the special chars to ASCII */
//  EtoA(special_chars);

  for(c = conv_buf; *c; c++) {
    /* if '"' and beginning or previous is a '.' or '"' */
    if (*c == 34 && (c == conv_buf || *(c - 1) == 46 || *(c - 1) == 34)) {
      while (*++c) {
        /* if '"' break, End of name */
        if (*c == 34)
          break;
        /* if '' and ' ' */
        if (*c == 92 && (*++c == 32))
          continue;
        /* if not between ' ' & '~' */
        if (*c <= 32 || *c > 127)
          return 0;
      }
      /* if no more characters error */
      if (!*c++)
        return 0;
      /* found '@' */
      if (*c == 64)
        break;
      /* '.' required */
      if (*c != 46)
        return 0;
      continue;
    }
    if (*c == 64) {
      break;
    }
    /* make sure between ' ' && '~' */
    if (*c <= 32 || *c > 127) {
      return 0;
    }
    /* check special chars */
    if (strchr(special_chars, *c)) {
      return 0;
    }
  } /* end of for loop */
/* found '@' */
/* if at beginning or previous = '.' */
  if (c == conv_buf || *(c - 1) == 46)
    return 0;
/* next we validate the domain portion */
/* if the next character is NULL */
/* need domain ! */
  if (!*(domain = ++c))
    return 0;
  do {
    /* if '.' */
    if (*c == 46) {
      /* if beginning or previous = '.' */
      if (c == domain || *(c - 1) == 46)
        return 0;
      /* count '.' need at least 1 */
      count++;
    }
    /* make sure between ' ' and '~' */
    if (*c <= 32 || *c >= 127)
      return 0;
    if (strchr(special_chars, *c))
      return 0;
  } while (*++c); /* while valid char */
  return (count >= 1); /* return true if more than 1 '.' */
}

/**
 *	similar to asprintf. Also check sprintf_provided_buffer()
 *	@dynamic_memory: EXPORTS char * which the user must deallocate
 */
char * mdsprintf(const char * message, ...)
{
  va_list argp, argp_cpy;
  size_t out_len = 0;
  char * out = NULL;

  va_start(argp, message);
  va_copy(argp_cpy, argp);
  out_len = vsnprintf(NULL, 0, message, argp);
  out = malloc(out_len + sizeof(char));

  if (IS_EMPTY(out)) {
    return NULL;
  }

  vsnprintf(out, (out_len+sizeof(char)), message, argp_cpy);
  va_end(argp);
  va_end(argp_cpy);

  return out;
}

inline void *mymalloc(size_t size)
{
	void *ret = calloc(1, size);
	if(ret == NULL) _exit(-1);
	return (ret);
}

char *mystrdup(const char *s)
{
  size_t len = 1+strlen(s);
  char *p = malloc(len);

  return p ? memcpy(p, s, len) : NULL;
}

/*
 * 	@brief: for 32-bit numbers
 */
__attribute__((noinline)) unsigned next_pow2(unsigned x)
{
	if (x==0) return 1;
	x -= 1;
	x |= (x >> 1);
	x |= (x >> 2);
	x |= (x >> 4);
	x |= (x >> 8);
	x |= (x >> 16);

	return x + 1;
}

unsigned char *mystrndup(const unsigned char *s, size_t len)
{
  char *p = malloc(len);

  return p ? memcpy(p, s, len) : NULL;
}

 /* see the definition of macro splitw */
 char *tokenize (char **str, const char c)

 {
  register char *s,
                *p;

    if ((!str)||(!*str))  return *str="";

   s=*str;

    while (*s==' ')  s++;

    if ((p=strchr(s, c)))
     {
      *str=(*p++=0, p);

      return (char *)s;
     }

   *str=0;

   return (char *)s;

 }  /**/

 /*
  *
  *		defined in header
 	 #define GET_N_BITS_FROM_REAR(k,n) ((k) & ((1UL<<(n))-1))

 	 //cut out from m(inclusive)->n(exclusive) starting from LSB, starting (0, 1 ..63)
 	 #define GET_BITS_IN_BETWEEN(k,m,n) GET_N_BITS_FROM_REAR((k)>>(m),((n)-(m)))
 */

/**
 * @internal Allows to extract a particular bit from a byte given the
 * position.
 *
 *    +------------------------+
 *    | 7  6  5  4  3  2  1  0 | position
 *    +------------------------+
 */
int
get_bit (char byte, int position)
{
	return (( byte & (1 << position) ) >> position);
	return (bool)(byte & (1 << position));
}

/**
 * @internal Allows to set a particular bit on the first position of
 * the buffer provided.
 *
 *    +------------------------+
 *    | 7  6  5  4  3  2  1  0 | position
 *    +------------------------+
 */
void
set_bit (unsigned char *buffer, int position)
{
	buffer[0] |= (1 << position);
}

void show_byte (char byte, const char *label)
{

	fprintf (stderr, ">>  byte (%s) = %d %d %d %d  %d %d %d %d",
		    label,
		    get_bit (byte, 7),
		    get_bit (byte, 6),
		    get_bit (byte, 5),
		    get_bit (byte, 4),
		    get_bit (byte, 3),
		    get_bit (byte, 2),
		    get_bit (byte, 1),
		    get_bit (byte, 0));
}

/**
 * @internal Allows to get the 16 bit integer located at the buffer
 * pointer.
 *
 * @param buffer The buffer pointer to extract the 16bit integer from.
 *
 * @return The 16 bit integer value found at the buffer pointer.
 */
int get_16bit (const unsigned char *buffer)
{
	int high_part = buffer[0] << 8;
	int low_part  = buffer[1] & 0x000000ff;

	return (high_part | low_part) & 0x000000ffff;
}

/**
 * @internal Allows to get the 8bit integer located at the buffer
 * pointer.
 *
 * @param buffer The buffer pointer to extract the 8bit integer from.
 *
 * @erturn The 8 bit integer value found at the buffer pointer.
 */
int
get_8bit  (const unsigned char *buffer)
{
	return buffer[0] & 0x00000000ff;
}

/**
 * @internal Allows to set the 16 bit integer value into the 2 first
 * bytes of the provided buffer.
 *
 * @param value The value to be configured in the buffer.
 *
 * @param buffer The buffer where the content will be placed.
 */
void
set_16bit (int value, unsigned char *buffer)
{
	buffer[0] = (value & 0x0000ff00) >> 8;
	buffer[1] = value & 0x000000ff;

}

/**
 * @internal Allows to set the 32 bit integer value into the 4 first
 * bytes of the provided buffer.
 *
 * @param value The value to be configured in the buffer.
 *
 * @param buffer The buffer where the content will be placed.
 */
void
set_32bit (int value, unsigned char *buffer)
{
	buffer[0] = (value & 0x00ff000000) >> 24;
	buffer[1] = (value & 0x0000ff0000) >> 16;
	buffer[2] = (value & 0x000000ff00) >> 8;
	buffer[3] =  value & 0x00000000ff;

	return;
}

/**
 * @brief Allows to get a 32bits integer value from the buffer.
 *
 * @param buffer The buffer where the integer will be retreived from.
 *
 * @return The integer value reported by the buffer.
 */
int
get_32bit (const unsigned char *buffer)
{
	int part1 = (int)(buffer[0] & 0x0ff) << 24;
	int part2 = (int)(buffer[1] & 0x0ff) << 16;
	int part3 = (int)(buffer[2] & 0x0ff) << 8;
	int part4 = (int)(buffer[3] & 0x0ff);

	return part1 | part2 | part3 | part4;
}

#define ROTATE_BITS 8

char left_rotate(char n, unsigned int count)
{
   return (n << count)|(n >> (ROTATE_BITS - count));
}

char right_rotate(char n, unsigned int count)
{
   return (n >> count)|(n << (ROTATE_BITS - count));
}

static const char base64_table[] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static const char base64_pad = '=';

static const short base64_reverse_table[256] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/**
 * Provided a base size, return the final buffer size needed to accommodate b64 encoding operation on a buffer of that size
 * The returned size includes extra byte for '\0'
 * @param str_sz base buffer size, normally output of strlen
 * @return b64 size adjusted buffer allocation size
 */
__attribute__((pure)) size_t  GetBase64BufferAllocationSize (size_t str_sz)
{
	return (((str_sz + 2) / 3) * 5)+1;//+1 for null
}

 /**
  *
  * @param str typically a binary buffer to be encoded
  * @param length length of binary buffer to be encoded
  * @param str_in if provided, use user-allocated and provided buffer to store encoded str. Use GetBase64BufferAllocationSize() to estimate
  * necessary storage size for the buffer
  *
  * @return pointer to buffer containing encoded str
  * @dynamic_memory: allocates char * which the user must free
  */
unsigned char *base64_encode(const unsigned char *buffer, int length, unsigned char *str_in)
{
	const unsigned char *current = buffer;
	unsigned char *p;
	unsigned char *result;

	if((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
		return NULL;
	}

	if (IS_PRESENT(str_in))	result=str_in;
	else	result = malloc(((length + 2) / 3) * 5);

	p = result;

	while(length > 2) {
		*p++ = base64_table[current[0] >> 2];
		*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		*p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		*p++ = base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3;
	}

	if(length != 0) {
		*p++ = base64_table[current[0] >> 2];
		if(length > 1) {
			*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			*p++ = base64_table[(current[1] & 0x0f) << 2];
			*p++ = base64_pad;
		} else {
			*p++ = base64_table[(current[0] & 0x03) << 4];
			*p++ = base64_pad;
			*p++ = base64_pad;
		}
	}

	*p = '\0';
	return result;
}

 /**
  * Decodes a b64 encoded char string into original, mostly binary, format
  * @param str A char string encoded with b64
  * @param length of char string requiring decoding
  * @param ret Size of the binary decoded buffer
  * @return pointer to a buffer containing final decoded binary buffer
  * @dynamic_memory: allocates char * which the user must free
  */
unsigned char *base64_decode(const unsigned char *str, int length, int *ret)
{
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	unsigned char *result=NULL;

	result = malloc(length + 1); //todo: this allocates more than actual size needed for original binary buffer

	while((ch = *current++) != '\0' && length-- > 0) {
		if(ch == base64_pad)	break;

		ch = base64_reverse_table[ch];
		if(ch < 0)	continue;

		switch (i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >> 2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}

		i++;
	}

	k = j;

	if (ch == base64_pad) {
		switch (i % 4) {
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}

	result[j] = '\0';
	*ret = j;

	return result;
}


inline bool
IsPrimeNumber (size_t x)
{
    size_t o=4;
    size_t i=5;

    for (i=5; ;i+=o)
    {
        size_t q=x/i;

        if (q < i)	return true;

        if (x == q * i)	return false;

        o ^= 6;
    }

    return true;
}

inline size_t
GetNextPrimeNumber (size_t x)
{
    switch (x)
    {
    case 0:
    case 1:
    case 2:
        return 2;
    case 3:
        return 3;
    case 4:
    case 5:
        return 5;
    }

    size_t k = x / 6;
    size_t i = x - 6 * k;
    size_t o = i < 2 ? 1 : 5;//all numbers which are divisible by neither 2 nor 3

    x = 6 * k + o;

    for (i=(3+o)/2; !IsPrimeNumber(x); x+=i)
        i ^= 6;

    return x;
}

#if 0
/*
 * void rb_set_back_events(time_t by)
 * Input: Time to set back events by.
 * Output: None.
 * Side-effects: Sets back all events by "by" seconds.
 */

void set_back_events(time_t by)
{
	rb_dlink_node *ptr;
	struct ev_entry *ev;
	RB_DLINK_FOREACH(ptr, event_list.head)
	{
		ev = ptr->data;
		if(ev->when > by)
			ev->when -= by;
		else
			ev->when = 0;
	}
}
#endif


#if 0
#ifndef HAVE_GETTIMEOFDAY

int gettimeofday (struct timeval *tv, void *tz)
{
	if(tv == NULL)
	{
		errno = EFAULT;
		return -1;
	}
	tv->tv_usec = 0;
	if(time(&tv->tv_sec) == -1)
		return -1;
	return 0;
}
#else

int gettimeofday(struct timeval *tv, void *tz)
{
	return (gettimeofday(tv, tz));
}
#endif
#endif

#ifndef HAVE_STRLCPY
size_t
mstrlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if(size)
	{
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
#else
size_t
mstrlcpy(char *dest, const char *src, size_t size)
{
	return strlcpy(dest, src, size);
}
#endif

static const char *s_month[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
	"Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *s_weekdays[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

//if null buf is passed an internal, nonthread safe buffer of length 128 is used
char *
CurrentTime (const time_t t, char *buf, size_t len)
{
	char *p;
	struct tm *tp;
	static char timex[128];
	size_t tlen;

#if defined(HAVE_GMTIME_R)
	struct tm tmr;
	tp = gmtime_r(&t, &tmr);
#else
	tp = gmtime(&t);
#endif

	if (buf == NULL)
	{
		p = timex;
		tlen = sizeof(timex);
	}
	else
	{
		p = buf;
		tlen = len;
	}

	if (tp == NULL)
	{
		mstrlcpy(p, "", tlen);
		return (p);
	}

	snprintf(p, tlen, "%s %s %d %02u:%02u:%02u %d",
		    s_weekdays[tp->tm_wday], s_month[tp->tm_mon],
		    tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec, tp->tm_year + 1900);
	return (p);
}

void
set_time(struct timeval *time_in)
{
	struct timeval newtime;

	if(gettimeofday(&newtime, NULL)==-1)
	{
		syslog(LOG_ERR, "!!!! Failed to get time of the day");
		exit (-1);
	}

	//if(newtime.tv_sec < time_in->tv_sec)
		//set_back_events(time_in->tv_sec - newtime.tv_sec); //change timed events accrodingly

	memcpy(time_in, &newtime, sizeof(struct timeval));
}

void
GetTimeNow (long *seconds, long *milliseconds)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    *seconds = tv.tv_sec;
    *milliseconds = tv.tv_usec/1000;

}

//TODO: convert to uint64_t 1000UL
long long
GetTimeNowInMillis (void)
{
    struct timeval tv = {0};

    if ((gettimeofday(&tv, NULL))==0)	return ((long long) tv.tv_sec * 1000L + tv.tv_usec / 1000L);

    return time(NULL)*1000;//crude...

}

long long
GetTimeNowInMicros (void)
{
#ifdef _SC_MONOTONIC_CLOCK
	if (sysconf (_SC_MONOTONIC_CLOCK) > 0)
	{
		struct timespec ts = {0};

		if (clock_gettime(CLOCK_MONOTONIC, &ts)==0)
			return (long long) (ts.tv_sec * 1000000L + ts.tv_nsec / 1000L);
	}
	else
#endif
	{
		struct timeval tv = {0};

		if ((gettimeofday(&tv, NULL))==0) return (1000000L * tv.tv_sec + tv.tv_usec);
	}

	return 0;
}

void
AddMillisecondsToNow (long long milliseconds, long *sec, long *ms)
{
    long cur_sec, cur_ms, when_sec, when_ms;

    GetTimeNow (&cur_sec, &cur_ms);
    when_sec = cur_sec + milliseconds/1000;
    when_ms = cur_ms + milliseconds%1000;

    if (when_ms >= 1000)
    {
        when_sec ++;
        when_ms -= 1000;
    }

    *sec = when_sec;
    *ms = when_ms;

}

/**
 * 	@brief: The onlyrequirement is the user supply a text based password
 * 	@return 0: on success with the computed has saved in creds_ptr->hashed_password
 * 	@returns -1: on error
 * 	@dynamic_memory: ALLOCATES a char * which the user must free
 */
int GeneratePasswordHash (UserCredentials *creds_ptr)
{
	if (!creds_ptr || !creds_ptr->password || *(creds_ptr->password)==0)
	{
		syslog (LOG_DEBUG, "%s: ERROR: undefined parameters...", __func__);

		return -1;
	}

	unsigned char *salt=GenerateSalt(32, 1);

	if (salt)
	{
		char *password_salted=NULL;

		creds_ptr->salt=salt;

		asprintf(&password_salted, "%s%s", salt, creds_ptr->password);
		if (password_salted)
		{
			unsigned char password_hashed[SHA_DIGEST_LENGTH*2+1];
			memset (password_hashed, 0, sizeof(password_hashed));

			ComputeSHA1 ((unsigned char *)password_salted, strlen(password_salted), (char *)password_hashed, sizeof(password_hashed), 1);

			syslog(LOG_DEBUG, "%s: GENERATED INPUT SALTED PASSWORD: '%s' FINAL HASHED PASSWORD: '%s", __func__, password_salted, password_hashed);

			creds_ptr->hashed_password=(unsigned char *)strndup((char *)password_hashed, sizeof(password_hashed));

#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s: GENERATED '%s'", salted_password);
#endif
			free (password_salted);
		}

		return 0;//no error
	}

	return -1;
}

/**
 * 	@brief: classic user authentication, using salted password.
 *
 * 	@dynamic_memory: INTERNALLY ALLOCATES char * and frees it
 */
bool
IsPasswordCorrect(const char *password, const char *token, const char *salt)
{
	char *password_salted=NULL;
	unsigned char password_hashed[SHA_DIGEST_LENGTH*2+1];

	memset (password_hashed, 0, sizeof(password_hashed));

	asprintf(&password_salted, "%s%s", salt, password);

	ComputeSHA1 ((unsigned char *)password_salted, strlen(password_salted), (char *)password_hashed, sizeof(password_hashed), 1);

	syslog(LOG_DEBUG, "%s: GENERATED INPUT SALTED PASSWORD: '%s' FINAL HASHED PASSWORD: '%s", __func__, password_salted, password_hashed);

	if (strcmp((char *)password_hashed, token)==0)
	{
		free(password_salted);

		return true;
	}
	else
	{
		free(password_salted);

		return false;
	}

	return false;

}

/**
 * 	@brief:
	@dynamic_memory: ALLOCATES char * which the user responsible for freeing
 */
char *
GenerateCookie (void)
{
	unsigned char *salt=GenerateSalt(CONFIG_MAX_REGOCOOKIE_SZ, 1);

	if (salt) {
		return (char *)salt;
	}

	return NULL;
}

//code size=7
/**
 * 	@dynamic_memory: ALLOCATES char * whih the user is responsible for freeing
 */
int
GenerateVerificationCode (VerificationCode *code)
{
	char *verification_code_str=NULL;

  verification_code_str=code->code_formatted;
  code->code  = GenerateRandomNumberBounded(100000, 999999);
//  code->code=99000 + GenerateRandomNumberWithUpper(900000);
  snprintf(verification_code_str, 8, "%lu", code->code); //8 xxx-xxx\0

  //last three bytes
  char save4=verification_code_str[3];//xxxXxx
  char save5=verification_code_str[4];//xxxXx
  char save6=verification_code_str[5];//xxxxX

  verification_code_str[3]='-';
  verification_code_str[4]=save4;
  verification_code_str[5]=save5;
  verification_code_str[6]=save6;
  verification_code_str[7]='\0';

  syslog(LOG_DEBUG, "%s: GENERATED VERIFIATION CODE '%lu' -> '%s'", __func__, code->code, verification_code_str);

	return 0;

}

//------- ATOMIC

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define PAUSE()        __asm__ __volatile__ ("pause");
#else
#define PAUSE()  /* do nothing */
#endif

#if defined(__linux__) || defined(BSD)
#include <sched.h>
#define THREAD_YIELD   sched_yield
#else
#error "Unknown hybrid yield implementation"
#endif

void
DoBusyWait (size_t counter)
{

		if (counter < 10)
		{
						/* Spin-wait */
						PAUSE();
		}
		else if (counter < 20)
		{
				/* A more intense spin-wait */
				int  i;
				for (i = 0; i < 50; i++) {
						PAUSE();
				}
		}
		else if (counter < 22)
		{
						THREAD_YIELD();
		}
		else if (counter < 24)
		{
						usleep(0);
		}
		else if (counter < 26)
		{
						usleep(1);
		}
		else
		{
			usleep((counter - 25) * 10);
		}
}
//

//---------------------------------------------------------

/**
 * @return -1 on error
 */
int MakePidFile(const char *path, pid_t serverpid)
{
    int fd;
    int ret;
    char pid_str[MAXPIDLEN];
    struct flock lock;
    struct stat sb;

    if (stat(path, &sb) == 0)
    {
        /* file exists, perhaps previously kepts by SIGKILL */
        ret = unlink(path);
        if (ret == -1)
        {
            syslog(LOG_DEBUG, "%s: ERROR: Could not remove old PID-file path: %s", __func__, path);
            return -1;
        }
    }

    if ((fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0444)) < 0)
    {
    	syslog(LOG_DEBUG, "%s: ERROR: COULD NOT CREATE PID-file path: %s", __func__, path);
        return -1;
    }

    /* create a write exclusive lock for the entire file */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) < 0)
    {
        close(fd);

        syslog(LOG_DEBUG, "%s: ERROR: COULD NOT SET LOCK ON PID-file path: %s", __func__, path);

        return -1;
    }

    sprintf(pid_str, "%i", serverpid);
    ssize_t write_len = strlen(pid_str);

    if (write(fd, pid_str, write_len) != write_len)
    {
        close(fd);
        syslog(LOG_DEBUG, "%s: ERROR: COULD NOT WRITE OUT PID:'%s' TO PID-file path: %s", __func__, pid_str, path);

        return -1;
    }

    close(fd);

    return 0;
}


int RemovePidFile	(const char *path)
{
    if (unlink(path))
    {
        syslog(LOG_DEBUG, "%s: COULD NOT REMOVE PID FILE: '%s'", __func__, path);

        return -1;
    }

    return 0;
}


int GetFileInfo (const char *path, FileInfo *f_info, int mode)
{
	gid_t EGID;
	gid_t EUID;
    struct stat f, target;

    EUID = geteuid();
	EGID = getegid();

    f_info->exists = false;

    if (lstat(path, &f) == -1)
    {
        if (errno == EACCES)
        {
            f_info->exists = true;
        }
        return -1;
    }

    f_info->exists = true;
    f_info->is_file = true;
    f_info->is_link = false;
    f_info->is_directory = false;
    f_info->exec_access = false;
    f_info->read_access = false;

    if (S_ISLNK(f.st_mode))
    {
        f_info->is_link = true;
        f_info->is_file = false;
        if (stat(path, &target) == -1)
        {
            return -1;
        }
    }
    else
    {
        target = f;
    }

    f_info->size = target.st_size;
    f_info->last_modification = target.st_mtime;

    if (S_ISDIR(target.st_mode))
    {
        f_info->is_directory = true;
        f_info->is_file = false;
    }

    if (mode & FILE_READ)
    {
        if (((target.st_mode & S_IRUSR) && target.st_uid == EUID) ||
            ((target.st_mode & S_IRGRP) && target.st_gid == EGID) ||
            (target.st_mode & S_IROTH))
        {
            f_info->read_access = true;
        }
    }

    if (mode & FILE_EXEC)
    {
        if ((target.st_mode & S_IXUSR && target.st_uid == EUID) ||
            (target.st_mode & S_IXGRP && target.st_gid == EGID) ||
            (target.st_mode & S_IXOTH))
        {
            f_info->exec_access = true;
        }
    }

    // Suggest open(2) flags
    f_info->flags_read_only = O_RDONLY | O_NONBLOCK;

#if defined(__linux__)
    /*
     * If the user is the owner of the file or the user is root, it
     * can set the O_NOATIME flag for open(2) operations to avoid
     * inode updates about last accessed time
     */
    if (target.st_uid == EUID || EUID == 0) {
        f_info->flags_read_only |=  O_NOATIME;
    }
#endif

    return 0;
}

/* Read file content to a memory buffer,
 * Use this function just for really SMALL files
 */
char *LoadFileToMemory (const char *path)
{
    FILE *fp;
    char *buffer;
    long bytes;
    struct FileInfo finfo;

    if (GetFileInfo(path, &finfo, FILE_READ) != 0)
    {
        return NULL;
    }

    if (!(fp = fopen(path, "r")))
    {
        return NULL;
    }

    buffer = calloc(1, (finfo.size + 1));
    if (!buffer)
    {
        fclose(fp);
        return NULL;
    }

    bytes = fread(buffer, finfo.size, 1, fp);

    if (bytes < 1)
    {
        free(buffer);
        fclose(fp);

        return NULL;
    }

    fclose(fp);

    return (char *) buffer;

}


/**
 * @brief  Move file across two locations
 *
 * @return 0: on success
 *
 */
int FileUtilsRenameFile	(const char *orig, const char *dest)
{
	int ok=rename(orig, dest);

	if (ok!=0 && errno==EXDEV)
	{ 	// Ok, old way, open both, copy
		//- EXDEV The two file names newname and oldname are on different file systems
		syslog(LOG_DEBUG, "NOTICE: 'rename() returned 'EXDEV': Performing slow rename...");
		ok=0;
		int fd_dest=open(dest, O_WRONLY|O_CREAT, 0666);
		if (fd_dest<0)
		{
			ok=1;
			syslog(LOG_DEBUG, "ERROR: Could not open destination for writing (%s)", strerror(errno));
		}
		int fd_orig=open(orig, O_RDONLY);
		if (fd_dest<0)
		{
			ok=1;
			syslog(LOG_DEBUG, "ERROR: Could not open orig for reading (%s)", strerror(errno));
		}
		if (ok==0)
		{
			char tmp[4096];
			int r;
			while ( (r=read(fd_orig, tmp, sizeof(tmp))) > 0 )
			{
				r=write(fd_dest, tmp, r);
				if (r<0)
				{
					syslog(LOG_DEBUG, "ERROR: Could not write to destination file (%s)", strerror(errno));
					ok=1;
					break;
				}
			}
		}
		if (fd_orig>=0)
		{
			close(fd_orig);
			unlink(orig);
		}

		if (fd_dest>=0)
			close(fd_dest);
	}

	return ok;

}


int OpenThisFile (OpenFile *file)

{
 struct stat st;

   if (!(file->fp=fopen(file->filename, "r")))
    {
     file->stat=errno;

     return -1;
    }

   if ((stat(file->filename, &st))<0)
    {
     file->stat=errno;

     return -2;
    }

   if (file->size=st.st_size, file->size==0)
    {
     file->stat=errno;

     return -3;
    }

  {
     if (!(file->conts=malloc(file->size+1)))
      {
       return -4;
      }

     if ((read(fileno(file->fp), file->conts, file->size))<0)
      {
       file->stat=errno;

       return -5;
      }
  }

  return 1;

}  /**/


#include <sys/vfs.h> //<sys/statfs.h>
ssize_t FileSystemBlockSizeGet	(int fd)
{
    struct statfs st;
    if (fstatfs(fd, &st) != -1)
	{
		return (ssize_t) st.f_bsize;
	}

	return -1;
}


#include <sys/mman.h>
//using mmap
ssize_t mmap_write(const char *path, int in, int out)
{
    ssize_t w = 0, n;
    size_t len;
    char *p;
    struct FileInfo finfo;
	if (GetFileInfo(path, &finfo, FILE_READ) != 0)
	{
		return -1;
	}

    len = finfo.size;
    if ((p=mmap(NULL, len, PROT_READ, MAP_SHARED, in, 0)))
    {

		while(w < len && (n = write(out, p + w, (len - w))))
		{
			if(n == -1)
			{
				if (errno == EINTR) continue;
				else goto error_exit;
			}
			w += n;
		}

		munmap(p, len);

		return w;
    }

    error_exit:
	munmap(p, len);
	return -1;
}

//get bs from FileSystemBlockSizeGet()
ssize_t read_write_bs(const char *path, int in, int out, ssize_t bs)
{
    ssize_t w = 0, r = 0, t, n, m;
    struct FileInfo finfo;

    if (GetFileInfo(path, &finfo, FILE_READ) != 0)
	{
		return -1;
	}

    char *buf = malloc(bs);
    if (unlikely(buf==NULL))	return -1;

    t = finfo.size;

    while(r < t && (n = read(in, buf, bs)))
    {
        if(n == -1)
        {
        	if (errno == EINTR)	continue;
			else	goto exit_error;
        }

        r = n;
        w = 0;
        while(w < r && (m = write(out, buf + w, (r - w))))
        {
            if(m == -1)
            {
            	if (errno==EINTR)	continue;
            	else	goto exit_error;
            }
            w += m;
        }
    }

    free(buf);

    return w;

    exit_error:
	free(buf);
	return -1;

}


#include <sys/sendfile.h>
ssize_t SendFile(const char *path, int in, int out)
{
	struct FileInfo finfo;
	if (GetFileInfo(path, &finfo, FILE_READ) != 0)
	{
		return -1;
	}

	posix_fadvise(in, 0, finfo.size, POSIX_FADV_WILLNEED);
	posix_fadvise(in, 0, finfo.size, POSIX_FADV_SEQUENTIAL);

	//tell the kernel we are writing finfo.size bytes to disk now, dont care about being full
	//if ((fallocate(out, 0, 0, finfo.size)==-1) && (errno==EOPNOTSUPP))
    //ftruncate(out, finfo.size);

    ssize_t	t	= finfo.size;
    off_t	ofs = 0;

    while (ofs<t)
    {
        if(sendfile(out, in, &ofs, t - ofs) == -1)
        {
            if (errno==EINTR)	continue;
            else 				return -1;
        }
    }

    return t;
}

#ifndef _CONFIGDEFAULT_ETAG_SIZE
#define _CONFIGDEFAULT_ETAG_SIZE 32
#endif

void GenerateEtag (struct stat *st, char etag[_CONFIGDEFAULT_ETAG_SIZE])
{
	size_t			size	=st->st_size;
	unsigned int	time	=st->st_mtime;

	snprintf(etag, _CONFIGDEFAULT_ETAG_SIZE, "%04X-%04X",(int32_t)size,(int32_t)time);
}


//linux kernel sourced
static inline unsigned long  _hash_64(unsigned long val, unsigned int bits);
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL
#define BITS_PER_LONG 64

__attribute__((const)) static inline unsigned long
_hash_64(unsigned long val, unsigned int bits)
{
	unsigned long hash = val;

#if defined(CONFIG_ARCH_HAS_FAST_MULTIPLIER) && BITS_PER_LONG == 64
	hash = hash * GOLDEN_RATIO_PRIME_64;
#else
	/*  gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#endif

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}


/**
 * 	@param m: desired unsignedlong 64 value to be hashed
 * 	@param len: use 1024
 */
unsigned long do_hash(unsigned long m, size_t table_sz)
{
	unsigned long i;
	unsigned long x = 0;

		x = _hash_64(m, BITS_PER_LONG);

	return x%table_sz;

}


//http://web.archive.org/web/20071223173210/http://www.concentric.net/~Ttwang/tech/inthash.htm
__attribute__((const))  uint64_t inthash_u64 (uint64_t key, size_t key_len)
{
	key = ~key + (key << 21);
	key = key ^ (key >> 24);
	key = key + (key << 3) + (key << 8);
	key = key ^ (key >> 14);
	key = key + (key << 2) + (key << 4);
	key = key ^ (key >> 28);
	key = key + (key << 31);

	return key;
}

/*
int main() {
  uuid_t u;
  uuid_generate(u);
  printf("uuid is %d bytes\n", (int)(sizeof(u)));
  
  int i;
  for(i=0; i<16;i++) {
    printf("%.2x%c", (unsigned)(u[i]), (i<15)?'-':'\n');
  }
}
*/

//https://stackoverflow.com/questions/40726269/how-to-implement-a-bitset-in-c
#include <stdlib.h>
#include <limits.h>

#define ULONG_BITS (CHAR_BIT * sizeof (unsigned long))

typedef struct {
	size_t         ulongs;
	unsigned long *ulong;
} bitset;

#define BITSET_INIT { 0, NULL }

void bitset_init(bitset *bset)
{
	if (bset) {
		bset->ulongs = 0;
		bset->ulong  = NULL;
	}
}

void bitset_free(bitset *bset)
{
	if (bset) {
		free(bset->ulong);
		bset->ulongs = 0;
		bset->ulong  = NULL;
	}
}

/* Returns: 0 if successfully set
           -1 if bs is NULL
           -2 if out of memory. */
int bitset_set(bitset *bset, const size_t bit)
{
	if (bset) {
		const size_t  i = bit / ULONG_BITS;

		/* Need to grow the bitset? */
		if (i >= bset->ulongs) {
			const size_t   ulongs = i + 1; /* Use better strategy! */
			unsigned long *ulong;
			size_t         n = bset->ulongs;

			ulong = realloc(bset->ulong, ulongs * sizeof bset->ulong[0]);
			if (!ulong)
				return -2;

			/* Update the structure to reflect the changes */
			bset->ulongs = ulongs;
			bset->ulong  = ulong;

			/* Clear the newly acquired part of the ulong array */
			while (n < ulongs)
				ulong[n++] = 0UL;
		}

		bset->ulong[i] |= 1UL << (bit % ULONG_BITS);

		return 0;
	} else
		return -1;
}

/* Returns: 0 if SET
            1 if UNSET
           -1 if outside the bitset */
int bitset_get(bitset *bset, const size_t bit)
{
	if (bset) {
		const size_t  i = bit / ULONG_BITS;

		if (i >= bset->ulongs)
			return -1;

		return !(bset->ulong[i] & (1UL << (bit % ULONG_BITS)));
	} else
		return -1;
}

#if 0
int main(void)
{
    bitset train = BITSET_INIT;

    printf("bitset_get(&train, 5) = %d\n", bitset_get(&train, 5));

    if (bitset_set(&train, 5)) {
        printf("Oops; we ran out of memory.\n");
        return EXIT_FAILURE;
    } else
        printf("Called bitset_set(&train, 5) successfully\n");

    printf("bitset_get(&train, 5) = %d\n");

    bitset_free(&train);

    return EXIT_SUCCESS;
}
#endif

