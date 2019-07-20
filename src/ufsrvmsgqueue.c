

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <main.h>
#include <nportredird.h>
#include <session.h>
#include <sockets.h>
#include <stdarg.h> //va
#include <ufsrvmsgqueue.h>
#include <nportredird.h>
#include <redis.h>
#include <backendconfig_type.h>
#include <misc.h>
#include <net.h>
#include <sessions_delegator_type.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern ufsrv *const masterptr;
static void *MQSubRedisSendCommand (MessageQueueBackend *mq_ptr, const char *format, ...);
static void *MQRedisSendCommand (Session *sesn_ptr, const char *format, ...);

//When passing in_per_ptr we assume we are reinitialisng an existing backend
//free context and reallocate
MessageQueueBackend *
InitialiseMessageQueueBackend (MessageQueueBackend *in_per_ptr)
{

	struct BackendConfig config;
	struct timeval tv;
	char resolved_ip[SBUF];

	if((GenericDnsResolve(masterptr->ufsrvmsgqueue_address, resolved_ip, sizeof(resolved_ip)))<0)	 config.con_tcp.host="127.0.0.1";
	else	 config.con_tcp.host=resolved_ip;
	config.con_tcp.port=masterptr->ufsrvmsgqueue_port;
	config.type=SOCK_TCP;
	tv.tv_sec=0;
	tv.tv_usec=500000;//0.5 sec
	config.con_tcp.timeout=tv;

	MessageQueueBackend *mq_ptr=NULL;
	mq_ptr=(MessageQueueBackend *)InitialiseRedisBackend((RedisBackend *)in_per_ptr, &config);
	if (mq_ptr)
	{
		mq_ptr->send_command=(void *(*)())MQRedisSendCommand;
		mq_ptr->send_command_multi=(void *(*)())RedisSendCommandMulti;
		mq_ptr->init_connection=(MessageQueueBackend *(*)(MessageQueueBackend *))InitialiseMessageQueueBackend;
	}
	return mq_ptr;

}


/**
 * 	/param restart_flag reinitialise the context after disconnect
 *	/brief only one subscriber listener per ufsrv instance that listens for broadcasts by other ufsrv publishers
 */
MessageQueueBackend *
SetupMessageQueueSubscriber (int restart_flag)
{
	MessageQueueBackend *mq_ptr;

	syslog(LOG_INFO, "%s: Initialising MessageQueue Subscriber Listener Backend. RESTART_FLAG: '%d'...", __func__, restart_flag);

	if (restart_flag)
	{
		if ((mq_ptr=InitialiseMessageQueueBackend(masterptr->msgqueue_sub)))
		{
			mq_ptr->send_command=(void *(*)())MQSubRedisSendCommand;//this is session agnostic hence why a different send command function
		}
		else
		{
			syslog(LOG_INFO, "%s: ERROR: COULD NOT RE-INITIALISE MessageQueue Subscriber Listening Session...", __func__);
		}
	}
	else
	{
		mq_ptr=InitialiseMessageQueueBackend(NULL);
		if (mq_ptr)
		{
			syslog(LOG_INFO, "%s: Initialising MessageQueue Subscriber Listening Session...", __func__);
			Socket *s_ptr;
			xmalloc(s_ptr, (sizeof(Socket)));
			memset (s_ptr, 0, sizeof(Socket));

			s_ptr->type=SOCK_UFSRVQUEUESUB;
			s_ptr->sock=((redisContext *)(mq_ptr->persistance_agent))->fd;
			strcpy (s_ptr->address, "localhost");
			strcpy (s_ptr->haddress,masterptr->ufsrvmsgqueue_address);
			masterptr->msgqueue_sub=mq_ptr;
			mq_ptr->send_command=(void *(*)())MQSubRedisSendCommand;//override for the subscriber
		}
		else
		{
			syslog(LOG_INFO, "%s: ERROR: COULD NOT INITIALISE MessageQueue Subscriber Listening Session...", __func__);
		}
	}

	return mq_ptr;

}


/**
 * 	@brief: Worker specific send function for intra publishing via msg queue bus. Each worker maintains its own instance
 * 	of the connection.
 */

static void *
MQRedisSendCommand (Session *sesn_ptr, const char *format, ...)
{
	MessageQueueBackend *pers_ptr;

	//user session io worker thread's specific data
	if (sesn_ptr && sesn_ptr->msgqueue_backend && sesn_ptr->msgqueue_backend->persistance_agent)
	{
		pers_ptr=sesn_ptr->msgqueue_backend;
	}
	else
	{//use ufsrv worker thread's specific
		pers_ptr=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_msgqueue_pub_key);
		if (!pers_ptr || !pers_ptr->persistance_agent)
		{
			syslog(LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT FIND Persistence object...", __func__, pthread_self());

			return NULL;
		}
	}

	va_list ap;
	void *_reply = NULL;
	redisReply *reply;

	va_start(ap,format);
	_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
	va_end(ap);

	if (!_reply)
	{
		syslog(LOG_ERR, "%s (cid='%lu'): ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...", __func__, sesn_ptr?sesn_ptr->session_id:0, ((redisContext *)(pers_ptr->persistance_agent))->err, ((redisContext *)(pers_ptr->persistance_agent))->errstr);

		if (IS_PRESENT(((*pers_ptr->init_connection)(pers_ptr))))
		{
			va_start(ap, format);
			_reply = redisvCommand((redisContext *)pers_ptr->persistance_agent, format, ap);
			va_end(ap);

			if (IS_PRESENT(_reply))	return _reply;
		}

		return NULL;
	}

	return _reply;

}


/**
 * 	@brief: Subscriber specific send function. Currently only one thread uses this to listen in for sub/pub traffic
 */
static void *
MQSubRedisSendCommand (MessageQueueBackend *mq_ptr, const char *format, ...)
{
	void *_reply = NULL;

	if (mq_ptr)
	{
		va_list ap;
		redisReply *reply;

		va_start(ap,format);
		_reply = redisvCommand((redisContext *)mq_ptr->persistance_agent, format, ap);
		va_end(ap);

		if (!_reply)
		{
			syslog(LOG_ERR, "%s : ERROR ('%d'): REDIS COMMAND ERROR '%s': Attempting reconnection...", __func__,
					((redisContext *)(mq_ptr->persistance_agent))->err, ((redisContext *)(mq_ptr->persistance_agent))->errstr);

			if (IS_PRESENT(((*mq_ptr->init_connection)(mq_ptr))))
			{
				va_start(ap, format);
				_reply = redisvCommand((redisContext *)mq_ptr->persistance_agent, format, ap);
				va_end(ap);

				if (IS_PRESENT(_reply))	return _reply;
			}

			return NULL;
		}
	}

	return _reply;

}
