/*

    Copyright (C) 1999-2001  Ayman Akt
    Original Author: Ayman Akt (ayman@pobox.com)

 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <sockets.h>
#include <net.h>
#include <session.h>
#include <misc.h>
#include <redirection.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket_io.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <command_console_thread.h>


//global application context data
extern ufsrv *const masterptr;
static pthread_t th_command_console_client;

void *
ThreadCommandConsoleClient (void *ptr)

{
	Socket *s_ptr;
	Session *sesn_ptr;
	if (ptr)
	{
		sesn_ptr=(Session *)ptr;
		s_ptr=sesn_ptr->ssptr;
		while (1)
		{
			int x;
			fd_set fd,
					xfd;

			again:
			FD_ZERO(&fd);
			FD_ZERO(&xfd);

			FD_SET(s_ptr->sock, &fd);

			x=select(s_ptr->sock+1, &fd, NULL, NULL, NULL);

			if (x>0)  //readable input on one of the redirectors
			{
				if ((ReadFromSocketRaw (sesn_ptr, NULL))==-1)
				{
					pthread_exit(NULL);//error
				}

				//TODO: NOT IMPLEMENTED
				//if ((SendToSocketRaw (sesn_ptr, NULL))==0)
				{
					pthread_exit(NULL);//error
				}
			} //if x>0
			else
			if (x==0)  /* timeout */
			{

			}
			else
			if ((x==-1)&&(errno!=EINTR))  /* select error */
			{
				syslog(LOG_ERR, "ThreadCommandConsoleClient: ERROR: select");

				goto again;
			}

			goto again;
		}
	}//if

	return NULL;

}

static void _PrintSslError (int );

//s_ptr: command console listening socket
int AnswerCommandConsoleRequest (Socket *s_ptr)
{
	int nsocket,
	    sin_size,
	    opt = 1;
	char     *intra_redir;
	struct sockaddr_in hisaddr;

	sin_size = sizeof(struct sockaddr_in);

	nsocket = accept(s_ptr->sock, (struct sockaddr *)&hisaddr, (socklen_t *)&sin_size);

	if ((nsocket < 0) && (errno != EWOULDBLOCK))
	{
		syslog (LOG_ERR, "%s: ERROR: COULD NOT accept connection: %s",   __func__, strerror(errno));

		return 0;
	}

	setsockopt (nsocket, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(int));
	//up-to this point we have a fully connected socket
	{
    ERR_clear_error();

	  SSL_set_fd (masterptr->ufsrv_crypto.ssl_console, nsocket);
    int accept_return_status = SSL_accept(masterptr->ufsrv_crypto.ssl_console);
		if (accept_return_status <= 0) {
		  _PrintSslError(accept_return_status);
//			syslog (LOG_ERR, "%s: ERROR: COULD NOT ESTABLSIH SSL HANSHAKE: %s", __func__,  SSL_get_error(masterptr->ufsrv_crypto.ssl_console, accept_return_status));
			close (nsocket);

			return 0;
		}

		syslog (LOG_INFO, "%s: SUCCESS: SECURE COMMAND CONSOLE Session establsihed SSL: '%s' cipher: '%s'... " , __func__,
				SSL_get_version(masterptr->ufsrv_crypto.ssl_console), SSL_get_cipher(masterptr->ufsrv_crypto.ssl_console));


	}

	{
		Session *sesn_ptr = calloc(1, sizeof(Session));

		if (IS_PRESENT(sesn_ptr)) {
			Socket *s_ptr_console_client;
			xmalloc(s_ptr_console_client, (sizeof(Socket)));
			memset (s_ptr_console_client, 0, sizeof(Socket));

			s_ptr_console_client->sock = nsocket;
			strcpy (s_ptr_console_client->haddress, (char *)inet_ntoa(hisaddr.sin_addr));
			strcpy (s_ptr_console_client->address, "localhost");
			s_ptr_console_client->hport = ntohs(hisaddr.sin_port);
			s_ptr_console_client->port = 19700;

		   if (!(sesn_ptr = InstantiateSession(s_ptr, NULL, CALL_FLAG_HASH_SESSION_LOCALLY, -1))) {//thread-safe only called from this thread
			   close (nsocket);
			   free (s_ptr_console_client);

			   return 0;
			  }

		   sesn_ptr->ssptr = s_ptr_console_client;
		   sesn_ptr->session_crypto.ssl = masterptr->ufsrv_crypto.ssl_console;
		   SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SECURE);

		  // sesnptr->redirection_registry=(void *)rptr;
		} else {
			//Recycler instance
			SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_RECYCLED);
		   sesn_ptr->session_id = GenerateSessionId();
		}

		syslog(LOG_INFO, ">> %s: Command Console connection from '%s': Creating Command Console Client thread...", __func__, sesn_ptr->ssptr->haddress);
		pthread_create (&th_command_console_client, NULL, ThreadCommandConsoleClient, sesn_ptr);
	}

	return nsocket;

}

Socket *
SetupCommandConsole (void)
{
	int socket;

	if ((socket=SetupListeningSocket("127.0.0.1", masterptr->command_console_port, SOCK_TCP, SOCKOPT_IP4|SOCKOPT_REUSEADDRE)))
	{
		Socket *s_ptr;
		xmalloc(s_ptr, (sizeof(Socket)));
		memset (s_ptr, 0, sizeof(Socket));

		s_ptr->type=SOCK_COMMAND_CONSOLE;
		s_ptr->sock=socket;
		strcpy (s_ptr->address, "localhost");
		strcpy (s_ptr->haddress, "localhost");

		syslog(LOG_INFO, ">> AnswerCommandConsoleRequest: Successfully created Command Console on port %d (fd=%d)...", masterptr->command_console_port, s_ptr->sock);

		return s_ptr;
	}
	else
	{
		syslog(LOG_INFO, ">> AnswerCommandConsoleRequest: ERROR: COUL NOT create Command Console port %d (error: '%s')...", masterptr->command_console_port, strerror(errno));
	}

	return NULL;

}

static void _PrintSslError (int error_code)
{
  unsigned long err = ERR_get_error();
//  char *er=ERR_error_string(error_code, NULL);
  int parsed_error_code = SSL_get_error(masterptr->ufsrv_crypto.ssl_console, error_code);
  switch (parsed_error_code)
  {
    case SSL_ERROR_NONE:
    {
      // no real error, just try again...
      printf("SSL_ERROR_NONE (%d)(%s)\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    case SSL_ERROR_WANT_READ:
      printf("SSL_ERROR_WANT_READ (%d)(%s)\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;

    case SSL_ERROR_WANT_WRITE:
    {
      // socket not writable right now, wait a few seconds and try again...
      printf("SSL_ERROR_WANT_WRITE (%d)(%s)\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    case SSL_ERROR_ZERO_RETURN:
    {

      printf("SSL_ERROR_ZERO_RETURN (%d)(%s): The TLS/SSL connection has been closed (peer disconnected?).\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    case SSL_ERROR_SYSCALL:
    {
      printf("SSL_ERROR_SYSCALL (%d)(%s): Some I/O error occurred \n", error_code, ERR_error_string(ERR_get_error(), NULL));
      int last_err=ERR_peek_last_error();
      char *er = ERR_error_string(last_err, NULL);
      printf("SSL_ERROR_SYSCALL (%d)(%s): Last error in the queue \n", last_err, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    case SSL_ERROR_SSL:
    {

      printf("SSL_ERROR_SSL (%d)(%s): A failure in the SSL library occurred, usually a protocol error.\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    default:
    {
      printf("UNOWN SSL ERROR (%d)(%s)\n", error_code, ERR_error_string(ERR_get_error(), NULL));
      break;
    }

  }//switch
}