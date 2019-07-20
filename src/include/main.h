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
/*
**
**
MODULEID("$Id: main.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/
#ifndef MAIN_H
# define MAIN_H

#if __VALGRIND_DRD
#include <valgrind/valgrind.h>
# 	include <valgrind/drd.h>
# 	include <valgrind_drd_inlines.h>
#	include <valgrind/memcheck.h>
#endif

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <pthread.h>

#include <systemd/sd-daemon.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>      /* base64 encode/decode */
#include <openssl/md5.h> /* md5 hash */
#include <openssl/sha.h>
#include <curl/curl.h>

#include <log_message_literals.h>
#include <utils.h>
#include <main_types.h>

 #define xmalloc(x, y) \
         (x)=malloc ((y)); \
          if (!(x)) \
           { \
            printf("Unable to obtain additional memory--quiting\n"); \
            exit (1); \
           }

//#define container_of(ptr, type, member) ({                      \
 //       const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
 //       (type *)( (char *)__mptr - offsetof(type,member) );})

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define _LOG(x, ...)	syslog(x, __VA_ARGS__)
#define _LOGD(...)	syslog(LOG_DEBUG, __VA_ARGS__)
#define _LOGN(...)	syslog(LOG_NOTICE, __VA_ARGS__)
#define _LOGI(...)	syslog(LOG_INFO, __VA_ARGS__)

#define xfree(x) free((x)); (x)=NULL
#define log(x...) syslog(LOG_INFO|LOG_LOCAL7, x)
#define logf(x, y...) fprintf ((x)->logf.file, y)
#define say(x...) printf(x)
#define arethesame(x, y) (!strcasecmp((x), (y)))
#define mstrncpy(s, p, n) \
   strncpy (s, p, strlen(p)>n-1?n:strlen(p)+1); \
   s[n-1]='\0'

#define LUA_CTX masterptr->lua_ptr

#define BACKGROUND     (1<<9)

#define ALL      1
#define NUMBER   2
#define NAME     3
#define WILDCARD 4

#define MODE1 1
#define MODE2 2

#define MAXREDIRID  (MAXHOSTLEN+10)

//#define MINIBUF     50


#define NOTCONNECTED 1
#define CONNECTED    2
#define TRYING       4

#include <ufsrvresult_type.h>

/* mptr->flags */
#define DEV_RESERVED (0x1<<0)

 int main (int, char **);
 void *Thread (void *);
 void SetConfigurationDefaults (void);
 void CheckCommandLine (int, char **);
 void Help (void);

#endif

