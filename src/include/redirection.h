
#ifndef REDIREDCTION_H
# define REDIREDCTION_H
#if 0
#include <list.h>
//#include <user.h>
#include <session.h>
#include <protocol.h>


/*default: "dst_host:dst_port:redir_type"*/

 enum {
  REDIR_TCP=1, REDIR_UDP, REDIR_PROXY, REDIR_SINGLE_SERVER
  /*struct Redirection.redir_type*/
 };

 enum {
   CON_SSL, CON_NORMAL
   /*struct Redirection.connection_type*/
  };

 enum {
   PROTOCOL_WEBSOCKETS=0, PROTOCOL_HTTP, PROTOCOL_UF
   /*struct Redirection.protocol_type*/
  };

 enum {
  REDIR_ACCESS_MODE_DENY=1, REDIR_ACCESS_MODE_ALLOW 
  /*struct RedirectionAccessList.redir_access_mode*/
 };

 enum {
  REDIR_MODE_ACTIVE, REDIR_MODE_PASSIVE 
  /*struct Redirection.redir_mode*/
 };

 struct RedirectionAccessList {
  unsigned redir_access_mode; /*emum*/
  dList access_list; /*struct AccessListEntry*/
  List intraassoc_list; /*struct IntraRedirACLAssociation*/
 };
 typedef struct RedirectionAccessList RedirectionAccessList;

#if 0
  struct IntraRedirACLAssociation {
   char intraredir_id[MAXREDIRID]; /*string identifier for the group*/
   ListEntry *aclent;
 };
 typedef struct IntraRedirACLAssociation IntraRedirACLAssociation;
#endif


 struct Redirection {
  unsigned redir_type; //emum
  unsigned redir_mode; //emum
  unsigned protocol_type; //enum
  unsigned connection_type; //enum

  unsigned dst_port;
  unsigned listen_on_port;
  unsigned long max_connections;
  char dst_host[MAXHOSTLEN];
  char local_host[MAXHOSTLEN];
  char redir_id[MAXREDIRID]; /*string identifier for the group*/

  struct RedirectionAccessList redir_access_list;

	const Protocol *protocol_def_ptr;
 };
 typedef struct Redirection Redirection;


 int AddRedirection (Redirection *);
 void CleanupRedirectionEntry (Redirection *);
#endif
#endif

