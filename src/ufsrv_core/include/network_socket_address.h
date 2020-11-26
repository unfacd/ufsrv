/*
 * network_socket_address.h
 *
 *  Created on: 5 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_H_
#define SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_H_

#include <stdint.h>
#include <network_socket_address_type.h>

void InitNetworkSocketAddress (NetworkSocketAddress *sa, int af);
int NetworkSocketAddressInstantiate	(NetworkSocketAddress *socket_address_ptr, const char *addr, uint16_t port);

int ConvertSocketAddressToNetworkFormat (const char *addr, NetworkSocketAddress *sa);
int ConvertSocketAddressToReadableFormat (const NetworkSocketAddress *sa, char *buf, int size);
void NetworkSocketAddressSetInet4FromHost (NetworkSocketAddress *sa, uint32_t addr, uint16_t port);
void NetworkSocketAddressSetInet6FromHost (NetworkSocketAddress *sa, const uint8_t *addr, uint16_t port);
int NetworkSocketAddressSetLocalFromFd (int sock_fd, NetworkSocketAddress *local);
int NetworkSocketAddressSetPeerFromFd (int sock_fd, NetworkSocketAddress *local);
int NetworkSocketAddressSetInet6FromSockaddr(NetworkSocketAddress *sa, const struct sockaddr *s);
void NetworkSocketAddressSetPort(NetworkSocketAddress *sa, uint16_t port);
int NetworkSocketAddressGetAddressFamily (const NetworkSocketAddress *sa);
uint32_t NetworkSocketAddressGetInet4Address(const NetworkSocketAddress *sa);
void NetworkSocketAddressGetInet6Address(const NetworkSocketAddress *sa, uint8_t *addr);
int NetworSocketAddresssaToReadable (const NetworkSocketAddress *sa, char *buf, int size);
uint16_t NetworkSocketAddressGetPort (const NetworkSocketAddress *sa);
bool SocketAddressIsAttributeSet (const NetworkSocketAddress *sa, int flag);
uint32_t NetworkSocketAddressGetHashValue (const NetworkSocketAddress *sa, int flag);
void NetworkSocketAddressCopy	(NetworkSocketAddress *dst, const NetworkSocketAddress *src);
bool NetworkSocketAddressCompare (const NetworkSocketAddress *l, const NetworkSocketAddress *r, int flag);
bool NetworkSocketAddressIsLinkLocal (const NetworkSocketAddress *sa);
bool NetworkSocketAddressIsLoopback (const NetworkSocketAddress *sa);
bool NetworkSocketAddressIsAddressUnspecified(const NetworkSocketAddress *sa);



#endif /* SRC_INCLUDE_NETWORK_SOCKET_ADDRESS_H_ */
