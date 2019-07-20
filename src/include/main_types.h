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

#ifndef SRC_INCLUDE_MAIN_TYPES_H_
#define SRC_INCLUDE_MAIN_TYPES_H_

#include <stddef.h>

typedef void  ClientContextData;
typedef	void 	CommandContextData;
typedef void MessageContextData;
typedef void ItemContainer;

//A cannot be a regular C language expression and no macro expansion. However, if invoked from a macro, macro arguments are expanded
#define STRINGISE_NX(A) #A

//A macro expanded
#define STRINGISE(A) STRINGISE_NX(A)

//A permitted to be an expression
#define STRINGISE_EXPR(A) ((A),STRINGISE_NX(A))

//Concatenate preprocessor tokens A and B without expanding macro definitions. If invoked from a macro, macro arguments are expanded
#define CONCATENATE_NX(A, B) A ## B

//  Concatenate preprocessor tokens A and B after macro-expanding them.
#define CONCATENATE(A, B) CONCATENATE_NX(A, B)

#define CLIENT_CTX_DATA(x)	((ClientContextData *)x)
#define COMMAND_CTX_DATA(x)	((CommandContextData *)x)

#define CALLFLAGS_EMPTY 0

#define _LOCK_TRY_FLAG_FALSE	0
#define _LOCK_TRY_FLAG_TRUE		1

#define FLAG_SELF_DESTRUCT_TRUE   true
#define FLAG_SELF_DESTRUCT_FALSE  false


#define COLLECTION_TYPE(x)  ((collection_t	**)(x))

typedef struct ContextDataPair {
	ClientContextData *first;
	ClientContextData	*second;
} ContextDataPair;

//simple mechanism to describe dynamic arrays of objects
typedef void collection_t;
typedef struct CollectionDescriptor {
	collection_t	**collection;
	size_t			collection_sz;

	//void (*free_collection)(void *);
}	CollectionDescriptor;

typedef struct CollectionDescriptorPair {
	CollectionDescriptor 	first,
												second;
}	CollectionDescriptorPair;

typedef struct BufferDescriptor {
	char 		*data;
	size_t	size,
					size_max;
} BufferDescriptor;

//Generic specifier for amount of details to be generated for a give entitiy, eg json object
enum DigestMode {
	DIGESTMODE_FULL,
	DIGESTMODE_MODERATE,
	DIGESTMODE_BRIEF
};

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
#define likely(expr) __builtin_expect(!!(expr), 1)
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#else
#define likely(expr) (expr)
#define unlikely(expr) (expr)
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

#define INIT_FLAG_TRUE    true
#define INIT_FLAG_FALSE   false

#endif /* SRC_INCLUDE_MAIN_TYPES_H_ */
