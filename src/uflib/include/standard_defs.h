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

#ifndef UFSRV_STANDARD_DEFS_H
#define UFSRV_STANDARD_DEFS_H

#define SMALLBUF    150
#define MEDIUMBUF   300
#define LARGBUF     600
#define XLARGBUF    1024
#define XXLARGBUF   2048


#define MINIBUF	64
#define SBUF    128
#define	SMBUF		192
#define MBUF  	256
#define MLBUF		320
#define LBUF    512
#define XLBUF   1024
#define XXLBUF  2048
#define X3BUF		3072
#define X4BUF		4096
#define X5BUF		5120
#define X6BUF		6144
#define X7BUF		7168
#define X8BUF		8192
#define X9BUF		9216
#define X10BUF	10240
#define X11BUF	11264
#define MAXBUF	65535

#ifndef NULL
#define NULL ((void *)0)
#endif

#if !defined(false)
#  define false 0
#endif

#if !defined(true)
#  define true 1
#endif

#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif
#else
#ifndef likely
# define likely(expr) (expr)
#endif
#ifndef unlikely
# define unlikely(expr) (expr)
#endif
#endif

#define __unused				__attribute__((unused))
#define __pure					__attribute__((pure))
//#define __const					__attribute__((const))

#define IS_STR_LOADED(x)		(((x) != NULL) && ((*(x)) != '\0'))
#define IS_STR_EMPTY(x)		((*(x)) == '\0')
#define IS_EMPTY(x)		(x == NULL)
#define IS_PRESENT(x)	(x != NULL)
#define LOAD_NULL(x)  (x = NULL)

#define IS_OK(x)		(x)
#define NOT_OK(x)		(!(x))

//for bool types
#define IS_TRUE(x)		((x) == true)
#define IS_FALSE(x)		((x) == false)
#define NOT_TRUE(x)		((x) == 0)

#endif //UFSRV_STANDARD_DEFS_H
