
#ifndef SRC_INCLUDE_VECTOR_TYPE_H_
#define SRC_INCLUDE_VECTOR_TYPE_H_


struct onion_block_t {
	char *data;
	int size;
	int maxsize;
};

typedef struct onion_block_t Vector;
typedef struct onion_block_t onion_block;

#endif /* SRC_INCLUDE_VECTOR_T_H_ */
