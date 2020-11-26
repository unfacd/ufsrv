/*
** net.h Copyright (c) 1998 Ayman Akt
**
** See the COPYING file for terms of use and conditions.
**
MODULEID("$Id: net.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/

#ifndef NET_H
# define NET_H

#include <network_socket_address_type.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <session_type.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <sockets.h>

/* struct resolved {
         char dns[MAXHOSTLEN];
         char dotted[14];
         unsigned long ip;
        };
*/
 struct ResolvedAddress {
        char dns[MAXHOSTLEN],
             dotted[MAXHOSTLEN];
        unsigned flags;
        struct in_addr inetaddr;
       };
 typedef struct ResolvedAddress ResolvedAddress;


int SetupListeningSocket (const char *, unsigned, unsigned, unsigned);
void FetchLocalhost (void);
int InitTelnet (void);
int isdottedquad (const char *);
int RequestTCPSocket (void);
int SetSocketFlags (int, int, int);
int ResolveAddress (const char *, ResolvedAddress *);
int ConnectToServer (const char *, unsigned long, Socket *);
int ConnectToServerSecure (const char *server, unsigned long port, SSL_CTX *ctx, Session *sesn_ptr);
int Connect (struct in_addr *, unsigned long, bool);
void nslookup (char *);
char *RawIPToDotted (unsigned long);
char *HostToDotted (char *);
char *DottedToHost (char *);
struct in_addr *NetworkToAddress (const char *);
char *AddressToNetwork (struct in_addr *);
int ServiceToPort (const char *, unsigned short);
char *PortToService (int, unsigned short);
char *ProtocolToName (unsigned short);
struct in_addr NetworkPrefixToAdress (unsigned int);
int IsLocalIP (const char *);
int IsSocketAlive (int socket);
int GenericDnsResolve (const char *host, char *ipbuf, size_t ipbuf_len);
//int TcpSocketOptionSetLinger (int fd);
int SocketOptionSetLINGER (int);
int SocketOptionSetLargeRCVBUF (int sock_fd);
int SocketOptionSetLargeSNDBUF (int sock_fd);
int SocketOptionSetREUSEPORT (int sock_fd, int reuse);
int  SocketOptionSetREUSEADDR(int sock_fd, int reuse);
int SocketOptionSetIP_PKTINFO(int sock_fd, int on);

#if !(HAVE_HSTRERROR)
 char *h_strerror (int);
# define hstrerror h_strerror
#endif
 unsigned long atoul_ (char *) __attribute__ ((deprecated("use strtoul instead")));

 #endif
