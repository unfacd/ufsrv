/*
 * client_thread.c


 *
 *  Created on: 15 Aug 2015
 *      Author: ayman
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <session.h>
#include <sys/prctl.h>//for naming thread
#include <ufsrvmsg_core/protocol/protocol_type.h>
#include <protocol/protocol_io.h>
#include <session_service.h>
#include <sessions_delegator_type.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

//typedef struct SessionsDelegator SessionsDelegator;
extern  const  Protocol *const protocols_registry_ptr;
extern SessionsDelegator *const sessions_delegator_ptr;

static void ShowCerts(SSL* ssl);

inline unsigned long
GenerateSessionId (void)
{

		  return (abs((unsigned long)(rand() * rand()) << 1));

}



/**
 * param protocol_id: >=0 protocol id which can be used as index. If -1 no protocol is associated with this session
 */
 Session *
InstantiateSession (Socket *ssptr, Socket *dsptr, unsigned call_flags, int protocol_id)

{
	Session *sesn_ptr;
	extern Protocol *ProtocolGet (unsigned protocol_id);

	sesn_ptr=calloc(1, sizeof(Session));

	if (!CreateSessionService(sesn_ptr))
	{
		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT CREATE SESSION SERVICE...", __func__, pthread_self());

		goto final_clean_up;
	}

	pthread_rwlockattr_init(&(sesn_ptr->session_events.rwattr));
	int rc=pthread_rwlock_init(&(sesn_ptr->session_events.rwlock), &(sesn_ptr->session_events.rwattr));//==0 on success
	if (rc==0)
	{
		sesn_ptr->when=time(NULL);
		sesn_ptr->session_id=GenerateSessionId();

		if (ssptr)
		{
			//TODO: consider using local variable
			pthread_mutexattr_t attr;

			//Note: using adaptive mutex changes the error reporting behaviour in lock/unlock it would appears multipe locks acquired at the same time
			pthread_mutexattr_init(&(sesn_ptr->message_queue_in.mutex_attr));
			pthread_mutexattr_settype(&(sesn_ptr->message_queue_in.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

			if ((pthread_mutex_init (&(sesn_ptr->message_queue_in.mutex), 	&(sesn_ptr->message_queue_in.mutex_attr)))!=0)
			{
				syslog(LOG_ERR, "%s (pid:'%lu', errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR INCOMING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
				pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

				goto final_clean_up;
			}

			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

			///////////////

			pthread_mutexattr_init(&(sesn_ptr->message_queue_out.mutex_attr));
			pthread_mutexattr_settype(&(sesn_ptr->message_queue_out.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

			if ((pthread_mutex_init (&(sesn_ptr->message_queue_out.mutex), 	&(sesn_ptr->message_queue_out.mutex_attr)))!=0)
			{
				syslog(LOG_ERR, "%s (pid:'%lu' errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR OUTGOING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
				pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

				goto final_clean_up;
			}

			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

			sesn_ptr->ssptr=ssptr;
		}

		if (dsptr)	sesn_ptr->dsptr=dsptr;


		//invoke protocol session specific initialisation for this session
		{
			if (protocol_id>=0)
			{
				//1) assign static protocol type data
				SESSION_PROTOCOLTYPE(sesn_ptr)=(ProtocolTypeData *)ProtocolGet(protocol_id);
				//TODO: this is to be phased out infavour of protocol_type_data
				sesn_ptr->protocol_registry=(void *)&protocols_registry_ptr[protocol_id];

				//2)assign dynamic protocol type session data (per session)
				if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, protocol_id))
				{
#define SESSION_RECYCLERINSTANCE	0
					_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, protocol_id, sesn_ptr, SESSION_RECYCLERINSTANCE);
#undef	SESSION_RECYCLERINSTANCE
				}
			}
		//	HTTP_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, sesn_ptr, 1);

			//old
			//SESSION_HTTP_REQUEST(sesn_ptr)->headers=onion_dict_new();
			//onion_dict_set_flags(SESSION_HTTP_REQUEST(sesn_ptr)->headers, OD_ICASE);
		}

		if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY)
		{
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)sesn_ptr)))
			{
				//TODO: CLEANUP: FREE object and mutextes
				//return NULL;
				goto mutex_clean_up;
			}
		}

		return (Session *)sesn_ptr;
	}
	else
	{
		char error_str[250];
		strerror_r(errno, error_str, 250);

		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR (errno='%d' str='%s'): COULD NOT INITIALISE MUTEX",
				__func__, pthread_self(), errno, error_str);

		goto final_clean_up;
		//free (sesn_ptr);
	}

	//return NULL;

	mutex_clean_up:
	pthread_rwlockattr_destroy(&(sesn_ptr->session_events.rwattr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

	pthread_rwlock_destroy(&(sesn_ptr->session_events.rwlock));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_in.mutex));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_out.mutex));
	//TODO: CLEAN UP PROTOCOL INIT

	goto final_clean_up;

	//
	final_clean_up:
	free (sesn_ptr);

	return NULL;

}  /**/


 unsigned
 CreateSessionService (Session *sesn_ptr)

 {

 	if (!InitialiseUserBackendAccess(&(sesn_ptr->sservice)))
 	{
 		syslog(LOG_ERR, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT INITIALISE UserBackendAccess...", __func__, pthread_self(), SESSION_ID(sesn_ptr));

 		return 0;
 	}


 	//perform user semantics checking
 	return 1;

 }	  /**/

 static void InitHTTPClient(void)

 {
 	fprintf(stderr, ">>> Initialisaing HTTPClient subsystem...\n");

 	curl_global_init(CURL_GLOBAL_ALL);
 }

 void *ThreadClient(void *ptr)
{
	Session *sesn_ptr;
	SSL_CTX *ctx = NULL;//=(SSL_CTX *)ptr;

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufClientWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}
	
	{
		if (SSL_library_init() < 0)
		{
			fprintf(stderr, "Could not initialize the OpenSSL library !\n");
			_exit(-1);
		}

		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
			fprintf(stderr, "Unable to create a new SSL context structure.\n");
			_exit(-1);
		}

		const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(ctx, flags);
		//Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_client_cert_cb(ctx, NULL);
		SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}

	InitHTTPClient();

	Socket *ssptr = calloc(1, (sizeof(Socket)));
	sesn_ptr      = InstantiateSession(ssptr, NULL, 0, 0);

	if (!BackendSignUpUser(sesn_ptr)) {
		fprintf(stderr, "(pid:'%lu' cid:'%lu') >> COULD NOT SIGNUP USER: Exiting\n", pthread_self(), SESSION_ID(sesn_ptr));
		goto exit_error;
	}

	char *handshake_str;
	//use with direct unproxied connection
	asprintf(&handshake_str, "GET /?since_id=6 HTTP/1.1\r\nHost: 139.162.1.245\r\nOrigin: http://139.162.1.245\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: pfx+/BoQNN1TSdIz3FjLqw==\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: chat, superchat\r\nCookie: %s\r\nX-UFSRVCID: 0\r\nX-Forwarded-For: 139.162.1.245\r\n\r\n",
	//use this when proxying through haproxy as it doesnt include the X-Forearded for header
	//asprintf(&handshake_str, "GET /?since_id=6 HTTP/1.1\r\nHost: 139.162.1.245\r\nOrigin: http://139.162.1.245\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: pfx+/BoQNN1TSdIz3FjLqw==\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: chat, superchat\r\nCookie: %s\r\nX-UFSRVCID: 0\r\n\r\n",

			sesn_ptr->session_cookie);

	//syslog(LOG_INFO, "ThreadClient (pid='%lu' cid='%lu'): SENDING: '%s'", pthread_self(), sesn_ptr->session_id, handshake_str);


	//if (ConnectToServerSecure("139.162.1.245",19702, ctx, sesn_ptr))
	if (ConnectToServer("127.0.0.1", 19701, sesn_ptr->ssptr))
	{
		//ShowCerts(sesn_ptr->session_crypto.ssl);

		fprintf(stderr, "\n>>> Main loop (pid:'%lu' cid:'%lu'): Sending Websocket handshake....\n", pthread_self(), SESSION_ID(sesn_ptr));
		SendTextMessage(sesn_ptr, handshake_str, strlen(handshake_str));//SendToSocketRaw (sesn_ptr, handshake_str);
		free(handshake_str);
	}
	else
	{
		perror(" could not connect to server...\r\n");
		exit (-1);
	}


	// Set timeout to 1.0 seconds
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	{//start block
		while (1)
		{
			int x;
			fd_set fd,
					xfd;
			char xbuf[XXLBUF ]= {0};
			int buflen = 0;

			again:
			fprintf(stderr, ">>> Main loop (pid:'%lu' cid:'%lu'): Entering select....\n", pthread_self(), sesn_ptr->session_id);

			FD_ZERO(&fd);
			FD_ZERO(&xfd);

			FD_SET(sesn_ptr->ssptr->sock, &fd);

			x = select(sesn_ptr->ssptr->sock+1, &fd, NULL, NULL, NULL);//&timeout);

			if (x > 0)  //readable input on one of the redirectors
			{
				if (FD_ISSET(sesn_ptr->ssptr->sock, &fd))
				{
					if (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_HANDSHAKED))
					{
						//read off the return WS handshake by the server. We do nothing with it
						fprintf(stderr, ">>> Main loop (pid:'%lu' cid:'%lu'): Readable input: checking handshake reply....\n", pthread_self(), SESSION_ID(sesn_ptr));
						ProcessIncomingWsHandshakeAsClient(sesn_ptr, SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr));

						if (SESSION_RESULT_TYPE_ERROR(sesn_ptr))	pthread_exit(NULL);

						if (SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr) > 0)
						{
							UFSRVResult *res;
							//dequeue into the trasitional buffer &(sesn_ptr->ssptr->socket_msg)
							res = proto_websocketclient_msg_callback(sesn_ptr, &(sesn_ptr->ssptr->socket_msg), SOCKMSG_READBUFFER|SOCKMSG_READQUEUE);
						}

						goto again;
					}

					__main_input_reader:
					#if 1
					fprintf(stderr, ">>> Main loop (pid:'%lu' cid:'%lu'): Readable input: Checking server packets..\n", pthread_self(), sesn_ptr->session_id);
					if (_PROTOCOL_CLLBACKS_MSG(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
					{
						UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_MSG_INVOKE(protocols_registry_ptr,
															PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
															sesn_ptr, SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr), SOCKMSG_READSOCKET, 0);


						switch (res_ptr->result_type)
						{
							case RESULT_TYPE_PROTOCOLERR:
							case RESULT_TYPE_IOERR:
							case RESULT_TYPE_ERR:

								_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);

							default:
								//reset buffer
							{
								SocketMessage *sock_msg_ptr=SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr);
								free(sock_msg_ptr->_processed_msg);
								sock_msg_ptr->_processed_msg=0;
								sock_msg_ptr->processed_msg_size=0;
							}
								_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED);
						}
					}
					else
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO MSG CALLBACK DEFINED FOR PROTOCOL (id:'%d', name:'%s')", __func__, sesn_ptr->pid, SESSION_ID(sesn_ptr),
								PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))), PROTO_PROTOCOL_NAME(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));
					}
					#endif
					//end main_input_reader

#if 0
					//old
					int result=ReadFromSocketWS (sesn_ptr, xbuf, buflen); buflen=0;
					if (result<0)
					{
						fprintf (stderr, "(pid:'%lu' cid:'%lu') >> I/O error: shutting down...\n", pthread_self(), sesn_ptr->session_id);
						pthread_exit(NULL);
					}
					else
					if (result==0)
					{
						//orderly shutdown
						fprintf (stderr, "(pid:'%lu' cid:'%lu') >> decoding error (result='%d')...\n", pthread_self(), sesn_ptr->session_id, result);
						continue;
					}
#endif
#if 0
					char *res;
					int loop_counter=sesn_ptr->ssptr->frame_count;//get_16bit(sesn_ptr->ssptr->msg_out2);
					char *aux=sesn_ptr->ssptr->msg_out2;
					int len=strlen(sesn_ptr->ssptr->msg_out2);
					int offset=0;

					if (sesn_ptr->ssptr->missing_msg_size>0)
					{
						fprintf (stderr, "(pid:'%lu' cid:'%lu') >> Buffer has missing bytes '%d'\n", pthread_self(), sesn_ptr->session_id, sesn_ptr->ssptr->missing_msg_size );
						/*if (!--loop_counter)
						{
							fprintf (stderr, ">> Buffer has missing bytes '%d': loop counter is '0'\n", sesn_ptr->ssptr->missing_msg_size );
							continue;
						}*/
					}

					//this is the first msg

					while (loop_counter--)
					{
						fprintf (stderr, ">> (pid:'%lu' cid:'%lu'): decoding offset '%d'. str: '%s'\n", pthread_self(), sesn_ptr->session_id, offset, sesn_ptr->ssptr->msg_out2+offset );

						if ((res=ParseServerCommand(sesn_ptr, offset)))
						{
							if ((SendToSocketRaw (sesn_ptr, NULL))==0)
							{
								pthread_exit(NULL);//error
							}
						}
						//memory layout  +-------+-------+
						//						'0'		'0'
						//				str1	str2	str3
						//						offset=str1+strlen(str1)+1
						offset+=len;//remember last len
						len=strlen(sesn_ptr->ssptr->msg_out2+(++offset));//increment offset to past the '0'then read the length upto the next '0'
					}

					//remember location of incomplete buffer
					if (sesn_ptr->ssptr->missing_msg_size>0)
					{
						//offset+=len;//remember last len
						//offset++;//go past the '0'
						//sesn_ptr->ssptr->holding_buffer=mystrndup(sesn_ptr->ssptr->msg_out2+offset, sesn_ptr->ssptr->raw_unprocessed_msg_size);//len);
						//fprintf (stderr, ">> Offset: '%d' SAVED holding buffer size:'%d' buf: '%s'\n", offset, sesn_ptr->ssptr->raw_unprocessed_msg_size, sesn_ptr->ssptr->holding_buffer );
					}
#endif


				}//ISSET
			} //if x>0
			else
			if (x==0)  /* timeout */
			{
				//ufcltSendLocation (sesn_ptr);
			}
			else
			if ((x==-1)&&(errno!=EINTR))  /* select error */
			{
				fprintf(stderr, "(pid:'%lu' cid:'%lu') ThreadClient: ERROR: select\n", pthread_self(), sesn_ptr->session_id);

				goto again;
			}

			goto again;
		}//while
	}//end block


	exit_error:
		fprintf(stderr, "(pid:'%lu' cid:'%lu') >> Exiting\n", pthread_self(), sesn_ptr->session_id);

	return 0;//ret;

}

 static void ShowCerts(SSL* ssl)
 {   X509 *cert;
     char *line;

     cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
     if ( cert != NULL )
     {
         printf("Server certificates:\n");
         line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
         printf("Subject: %s\n", line);
         free(line);       /* free the malloc'ed string */
         line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
         printf("Issuer: %s\n", line);
         free(line);       /* free the malloc'ed string */
         X509_free(cert);     /* free the malloc'ed certificate copy */
     }
     else
         printf("Info: No client certificates configured.\n");
 }

 static void do_ssl_shutdown(SSL *ssl)
 {
#if 0
     int ret;

     do {
         /* We only do unidirectional shutdown */
         ret = SSL_shutdown(ssl);
         if (ret < 0) {
             switch (SSL_get_error(ssl, ret)) {
             case SSL_ERROR_WANT_READ:
             case SSL_ERROR_WANT_WRITE:
             case SSL_ERROR_WANT_ASYNC:
             case SSL_ERROR_WANT_ASYNC_JOB:
                 /* We just do busy waiting. Nothing clever */
                 continue;
             }
             ret = 0;
         }
     } while (ret < 0);
#endif
 }
