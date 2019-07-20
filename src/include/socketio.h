/*
** socketio.c Copyright (c) 1998 Ayman Akt
**
** See the COPYING file for terms of use and conditions.
**
MODULEID("$Id: socketio.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/

 int GetRegisteredSockets (int *);
 int AddtoQueue (Socket *);
 void AddtoSocketQueue (Socket *, char *, int);
 void RemovefromSocketQueue (Socket *, int *);

 int ToSocket (int, const char *, ...);
 int WriteToSocket (int, const char *);

