/*
** configfile.h Copyright (c) 1998 Ayman Akt
**
** See the COPYING file for terms of use and conditions.
**
MODULEID("$Id: configfile.h,v 1.1 1999/08/05 04:25:19 ayman Exp $")
**
*/

 #define SERVERS     1
 #define SETS        2
 #define UTMPNOTIFY  16
 #define INETNOTIFY  32

 #define THELOT \
 (SERVERS|SETS|UTMPNOTIFY|INETNOTIFY)

 int ProcessConfigfile (const char *);

