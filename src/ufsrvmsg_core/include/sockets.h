/*
** sockets.c Copyright (c) 1999 Ayman Akt
**
** See the COPYING file for terms of use and conditions.
**
MODULEID("$Id: sockets.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/

#ifndef SOCKETS_H
# define SOCKETS_H

#include <socket_type.h>
#include <sys/epoll.h>

 void InitSocketsTable (void);
 void TellSocketType (const Socket *, char *);
 void TellSocketInfo (const Socket *);
 void ShowSocketsTable (void);
 Socket *SocketByName (int);
 Socket *Socketbyaddress (const char *, int);
 void ConnectionLost (int);
 void setsockflag (int, int, bool);
 bool SocketQueueEmpty (Socket *);

#endif