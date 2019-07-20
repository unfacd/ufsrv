/*
 * network_socket_address_type.h
 *
 *  Created on: 5 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_TYPE_H_
#define SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_TYPE_H_


#include <netinet/in.h>
#include <sys/socket.h>

/** Socket Address flags */
enum sa_flag {
	SA_ADDR      = 1<<0,
	SA_PORT      = 1<<1,
	SA_ALL       = SA_ADDR | SA_PORT
};

//generic holder of network address
typedef struct NetworkSocketAddress {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		uint8_t padding[28];
	} u;

	socklen_t len;
}	NetworkSocketAddress;


#endif /* SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_TYPE_H_ */
