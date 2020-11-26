/*
 * dictionary_t.h
 *
 *  Created on: 27 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_DICTIONARY_TYPE_H_
#define SRC_INCLUDE_DICTIONARY_TYPE_H_

struct onion_dict_t{
	struct onion_dict_node_t *root;
#ifdef HAVE_PTHREADS
	pthread_rwlock_t lock;
	pthread_mutex_t refmutex;
#endif
	int refcount;
  int (*cmp)(const char *a, const char *b);
};

typedef struct onion_dict_t Dictionary;
typedef struct onion_dict_t onion_dict;


#endif /* SRC_INCLUDE_DICTIONARY_T_H_ */
