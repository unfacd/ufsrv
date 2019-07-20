/**
 * Copyright (C) 2015-2019 unfacd works
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrvresult_type.h>
#include <sockets.h>
#include <list.h>
#include <session.h>
#include <misc.h>
#include <nportredird.h>
#include <protocol.h>
#include <protocol_io.h>
#include <protocol_websocket.h>
#include <protocol_websocket_routines.h>
#include <protocol_websocket_io.h>
#include <instrumentation_backend.h>
#include "hiredis/hiredis.h"
#include <websocket_parser_type.h>
#include <WebSocketMessage.pb-c.h>
#include <ufsrvuid.h>

#define _RESET_BUFFERS\
	sm_ptr->processed_msg_size=0;\
	free (sm_ptr->_processed_msg);\
	sm_ptr->raw_msg_size=0;\
	free (sm_ptr->_raw_msg);\
	sm_ptr->missing_msg_size=0;\
	sm_ptr->holding_buffer_msg_size=0


/**
 * parse handshake headers
 *
 * @dynamic_memory: ALLOCATES SocketMessage 'char *_processed_msg' and 'char *_raw_msg' buffers. DEALLOCATES ON ERROR
 * Otherwise they must be freed when the handshake is successful by   ProcessOutgoingWsHandshake
 */
UFSRVResult *
ProcessIncomingWsHandshake (Session *sesnptr, SocketMessage *sock_msg_ptr)
{
    SocketMessage *sm_ptr;

	if (sock_msg_ptr) sm_ptr=sock_msg_ptr;
	else sm_ptr=&(sesnptr->ssptr->socket_msg);//default to incoming

	//when successful deallocate in ProcessOutgoingHandshake
	sm_ptr->_processed_msg=calloc(1, XLBUF);
	sm_ptr->_raw_msg=calloc(1, XLBUF);

	//if (!sock_msg_ptr)
	{
		sm_ptr->raw_msg_size=recv(sesnptr->ssptr->sock, sm_ptr->_raw_msg, XLBUF, 0);//masterptr->buffer_size

		if (sm_ptr->raw_msg_size==-1)
		{
			if (!(errno==EAGAIN) || !(errno==EWOULDBLOCK))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): REMOTE END CLOSED connection during handshake.", __func__, pthread_self(), SESSION_ID(sesnptr));

				_RESET_BUFFERS;

				_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspend
			}
			else
			{
				//blocking
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): COULD NOT READ INCOMING BUFFER: WOULD BLOCK", __func__, pthread_self(), SESSION_ID(sesnptr));

				//TODO: IMPLEMENT BLOCKING READ SEMANTICS FOR HANDSHAKE: at this stage we just terminate...
				_RESET_BUFFERS;

				_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_WOULDBLOCK);//we also suspend for this
			}
		}
		else
		if (sm_ptr->raw_msg_size==0)
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): REMOTE END CLOSED connection during handshake.", __func__, pthread_self(), SESSION_ID(sesnptr));

			_RESET_BUFFERS;

			_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspend
		}

		sm_ptr->_raw_msg[sm_ptr->raw_msg_size]=0;

		if (strstr((char *)sm_ptr->_raw_msg, "\r\n\r\n"))
		{
			//syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: FOUND HANDSHKE TERMINATION TOKEN", __func__, pthread_self(), SESSION_ID(sesnptr));
			//break;//end of stream
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT FIND HANDSHKE TERMINATION TOKEN", __func__, pthread_self(), SESSION_ID(sesnptr));

			_RESET_BUFFERS;

			_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);//suspend
		}
	}

    if ((memcmp(sm_ptr->_raw_msg, "\x16", 1) == 0) || (bcmp(sm_ptr->_raw_msg, "\x80", 1) == 0))
    {
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SSL connection request. Terminating: not supported.", __func__, pthread_self(), SESSION_ID(sesnptr));

		//TODO: remove the following 2 statements when SSL is ready
		_RESET_BUFFERS;

		//remove above wne SSL is READy
		_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_NOSSL);//suspend
    }
    else
    {
		//syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): USING NON-SSL connection.", pthread_self(), SESSION_ID(sesnptr));
    }


//parse handshake
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	if (!parse_handshake(sesnptr, (char *)sm_ptr->_raw_msg))
	{
		syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT PARSE Websocket handshake: Termination.", __func__, pthread_self(), SESSION_ID(sesnptr));

		_RESET_BUFFERS;

		_RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);//suspend
    }
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	//DONT DO THIS HERE. SHOULD BE DONE IN ProcessOutgoingWsHandshake
	//_RESET_BUFFERS;

	//this is no longer needed
	free (sm_ptr->_raw_msg);
	sm_ptr->raw_msg_size=0;

	_RETURN_RESULT_SESN(sesnptr, sesnptr, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_WSHANDSHAKE);

}

/**
 * @brief complete the WS handshake by responding to the client. We seperate this in order to perform internal lookup on the incoming cnnection
 * to ascertain its status and retrieve additional info to be included in the response header
 */
UFSRVResult *
ProcessOutgoingWsHandshake (Session *sesnptr, SocketMessage *sock_msg_ptr)
{
	char  sha1[29];

  Socket			*sptr = sesnptr->ssptr;
  int				sock = sptr->sock;
  SocketMessage	*sm_ptr;

	if (sock_msg_ptr) sm_ptr = sock_msg_ptr;
	else sm_ptr = &(sesnptr->ssptr->socket_msg);//default to incoming

	if (1) {//headers->hybi>0)
    gen_sha1(sptr, sha1);

    //construct the WS reply header. Append the session id if not present
    sprintf((char *)sm_ptr->_processed_msg, SERVER_HANDSHAKE_HYBI, sha1, "base64", SESSION_ID(sesnptr), UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesnptr)));
  }

#if 0
HTTP/1.1 101 Switching Protocols#015#012Upgrade: websocket#015#012Connection: Upgrade#015#012Sec-WebSocket-Accept: rjrmoqL0bOAvDJ4+K+cC1ftpqvg=#015#012Sec-WebSocket-Protocol: base64#015#012#015
#endif

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): Final handshake response: '%s'", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), sm_ptr->_processed_msg);
#endif

  sm_ptr->processed_msg_size = strlen((char *)sm_ptr->_processed_msg);
  sm_ptr->flag |= SOCKMSG_DONTWSFRAME;

  //TODO: port across so  this function doesnt use sm_ptr directly
  TransmissionMessage tms;
  tms.type = TRANSMSG_SOCKMSG;
  tms.msg = (void *)sm_ptr;

  int ret_value = SendToSocket(sesnptr, &tms, SOCKMSG_DONTWSFRAME);
  if (ret_value > 0) {
    //The Dispatch function is responsible for resetting incoming buffers sm_ptr once successfully processed into outgoing buffers
    sesnptr->stat |= SESNSTATUS_HANDSHAKED;

    _RETURN_RESULT_SESN(sesnptr, sesnptr, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_WSHANDSHAKE);
  }

  if (ret_value == -1) {
    //i/o error with suspension
    _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_SUSPENDED);
  }

  _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);

}

/**
 * 	@brief: Parses the server's return-WS-handshake as seen by a connecting client. Not used by the server.
 */
UFSRVResult *
ProcessIncomingWsHandshakeAsClient (Session *sesnptr, SocketMessage *sock_msg_ptr)
{
  SocketMessage *sm_ptr;
  unsigned char 			*handshake_end_pos;
  size_t 		layered_msg_sz=0;

  if (sock_msg_ptr) sm_ptr=sock_msg_ptr;
  else sm_ptr=&(sesnptr->ssptr->socket_msg);//default to incoming

  //when successful deallocate in ProcessOutgoingHandshake
  sm_ptr->_processed_msg=calloc(1, XLBUF);
  sm_ptr->_raw_msg=calloc(1, XLBUF);

  sm_ptr->raw_msg_size=read(sesnptr->ssptr->sock, sm_ptr->_raw_msg, XLBUF);//, 0);//masterptr->buffer_size

  if (sm_ptr->raw_msg_size==-1) {
    if (!(errno==EAGAIN) || !(errno==EWOULDBLOCK)) {
      syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): REMOTE END CLOSED connection during handshake.", __func__, pthread_self(), SESSION_ID(sesnptr));

      _RESET_BUFFERS;

      _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspend
    } else {
      //blocking
      syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): COULD NOT READ INCOMING BUFFER: WOULD BLOCK", __func__, pthread_self(), SESSION_ID(sesnptr));

      //TODO: IMPLEMENT BLOCKING READ SEMANTICS FOR HANDSHAKE: at this stage we just terminate...
      _RESET_BUFFERS;

      _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_WOULDBLOCK);//we also suspend for this
    }
  } else if (sm_ptr->raw_msg_size==0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): REMOTE END CLOSED connection during handshake.", __func__, pthread_self(), SESSION_ID(sesnptr));

    _RESET_BUFFERS;

    _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspend
  }

  //sm_ptr->_raw_msg[sm_ptr->raw_msg_size]=0;

  if ((handshake_end_pos=(unsigned char *)strstr((char *)sm_ptr->_raw_msg, "\r\n\r\n"))) {
    layered_msg_sz=sm_ptr->raw_msg_size-((handshake_end_pos+4)-sm_ptr->_raw_msg);
    syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: FOUND HANDSHKE TERMINATION TOKEN (handshake size:'%lu', layerd_sz:'%lu')", __func__, pthread_self(), SESSION_ID(sesnptr), (handshake_end_pos+4)-sm_ptr->_raw_msg, layered_msg_sz);
    //break;//end of stream
  } else {
    syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT FIND HANDSHKE TERMINATION TOKEN", __func__, pthread_self(), SESSION_ID(sesnptr));

    _RESET_BUFFERS;

    _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);//suspend
  }

  //[handshake\r\n\r\nxxxxxxxx0]
  //..........+ location of handshake_end_pos
  handshake_end_pos+=4; //skip the'\r\n\r\n'
  if (layered_msg_sz>0) {
    //we have some text to extract pas the handshake: shovel it into holding buffer
    SocketMessage *sm_ptr=calloc(1, sizeof(SocketMessage));

    sm_ptr->raw_msg_size=layered_msg_sz;
    sm_ptr->_raw_msg=(unsigned char *)strndup((char *)handshake_end_pos, layered_msg_sz);
    AddToQueue(&(sesnptr->message_queue_in.queue), sm_ptr);

//			sock_msg_ptr->holding_buffer_msg_size=layered_msg_sz;// strlen(handshake_end_pos);
//			sock_msg_ptr->holding_buffer=(unsigned char *)strndup(handshake_end_pos, layered_msg_sz);//sock_msg_ptr->holding_buffer_msg_size);

    fprintf(stderr, "HandshakeWebsocket (pid:'%lu' cid:'%lu'): FOUND LAYERD MSG (len: '%lu') '%.*s'...\n",
      pthread_self(), SESSION_ID(sesnptr), sm_ptr->raw_msg_size, (int)sm_ptr->raw_msg_size, sm_ptr->_raw_msg);
  }

  sock_msg_ptr->raw_msg_size=0;
  free (sock_msg_ptr->_raw_msg);
  free (sm_ptr->_processed_msg);
  sesnptr->stat|=SESNSTATUS_HANDSHAKED;

  _RETURN_RESULT_SESN(sesnptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_WSHANDSHAKE);

}

 //
 //should only be used with fully connected session, as it implements the WebSockets protoocl
 //static int _p_ReadFromSocket (Session *sesnptr, Socket *sptr)
 //
  int
  ReadFromSocketRaw (Session *sesn_ptr, SocketMessage *sock_msg_ptr)
  {
	  return 0;
#if 0
	  //enable with SocketMessage
 	char *wp_ptr=NULL;  //write back  buffer dynamically allocated by callback
 	int no_error=1; //default success
 	unsigned int opcode, left, ret;
 	unsigned int tout_start, tout_end, cout_start, cout_end;
 	unsigned int tin_start, tin_end;
 	ssize_t len=0, bytes;
 	int i;
 	SocketMessage *sm_ptr;

	if (sock_msg_ptr) sm_ptr=sock_msg_ptr;
	else sm_ptr=&(sesn_ptr->ssptr->socket_msg);

 	if (!sesn_ptr)
 	{
 		syslog (LOG_ERR, "ReadFromSocketRaw (pid:'%lu' cid:'%lu'): ERROR: Session is null", pthread_self(), sesn_ptr->session_id);

 		return -1;
 	}

 	tout_start=tout_end=cout_start=cout_end;
 	tin_start=tin_end=0;


	fd_set read_fds, write_fds, except_fds;
	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	FD_ZERO(&except_fds);
	FD_SET(sesn_ptr->ssptr->sock, &read_fds);

	// Set timeout to 1.0 seconds
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

     	// Wait for input to become ready or until the time out; the first parameter is
     	// 1 more than the largest file descriptor in any of the sets
     	if (select(sesn_ptr->ssptr->sock+1, &read_fds, &write_fds, &except_fds, &timeout) == 1)
     	{
     	    // fd is ready for reading
     		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE))
			{
     			sesn_ptr->ssptr->msglen=SSL_read(sesn_ptr->session_crypto.ssl,  sesn_ptr->ssptr->msg+tin_end, XLARGBUF);
			}
     		else
     		{
     			sesn_ptr->ssptr->msglen=read(sesn_ptr->ssptr->sock, sesn_ptr->ssptr->msg+tin_end, XLARGBUF);
     		}

 			//if ((sesn_ptr->ssptr->msglen=read(sesn_ptr->ssptr->sock, sesn_ptr->ssptr->msg+tin_end, XLARGBUF))>0)
     		if (sesn_ptr->ssptr->msglen>0)
 			{
 				bytes=sesn_ptr->ssptr->msglen;

 				//read  tin_end encoded bytes from a uf client
 				tin_end += bytes;

 				if (len<0)
 				{
 					syslog(LOG_ERR, "ReadFromSocketRaw (pid:'%lu' cid:'%lu'): ERROR (read <0). Connection"
 								" will be terminated", pthread_self(), sesn_ptr->session_id);

 					SuspendSession (sesn_ptr, 0);
 					return -1; //TODO: consider error handling outside this function
 				}//if len<0

 				if (left)
 				{
 					tin_start = tin_end - left;
 					syslog (LOG_INFO, "ReadFromSocketRaw (pid:'%lu' cid:'%lu'): partial frame from client.", pthread_self(), sesn_ptr->session_id);
 				}
 				else
 				{
 					tin_start = 0;//finished processing
 					tin_end = 0;
 				}


 				//tout_start = 0;
 				tout_end = len; //we are only wrting that much out not full len

 				return 1;

 			}//if msg_len>0
 			else //we read <=0
 			{
 				char *e_str=io_error(errno);

 				if (sesn_ptr->ssptr->msglen<0)
 				{
 					syslog(LOG_ERR, "ReadFromSocket (pid:'%lu' cid:'%lu')(ret:-1,errno:%d): %s. Connection will be closed.", pthread_self(), sesn_ptr->session_id, errno, e_str); free(e_str);

 					SuspendSession (sesn_ptr, 0);
 				}
 				else
 				{
 					if (!e_str)
 					/*{
 						syslog(LOG_INFO, "ReadFromSocket(ret:0,errno:%d): Reading from connection return '0' but no error was detected. We'll keep the connection on.", errno);
 					}
 					else*/
 					{
 						syslog(LOG_ERR, "ReadFromSocket (pid:'%lu' cid:'%lu')(ret:0,errno:%d): 'error not set. check return value.'. '0' was read and error detected. Connection will be closed.",
 								pthread_self(), sesn_ptr->session_id, errno); //we dont free e_str

 						SuspendSession (sesn_ptr, 0);
 					}
 				}//else

 				return -1;//error

 			}//else len<=0
     	}//select
 		else
 		{
 			syslog(LOG_ERR, "ReadFromSocket (pid:'%lu' cid:'%lu')(ret:0,errno:%d): SELECT TIMEOUT ERROR RETURNING...",
 									pthread_self(), sesn_ptr->session_id, errno); //we dont free e_str

 		}
#endif

 }

