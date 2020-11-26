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

#include <sys/prctl.h>//for naming thread
#include <nportredird.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>

extern ufsrv 							*const 	masterptr;
extern SessionsDelegator 	*const 	sessions_delegator_ptr;
static pthread_t 									th_msgqueue_sub;

static void *ThreadMessageQueueSub (void *);
static int _CreateMessageQueueTopics (MessageQueueBackend *, unsigned);

static char *subpub_verb = "message";

//subscriber thread for reading
/**
 * @brief: performs very rudimentary parsing of the stream. Hardcoded to parse 3-argument or 4-argument message only
 * it doesnt do proper checking on the fragmentation of message based on known packet size.
 *
 */
static void *
ThreadMessageQueueSub (void *ptr)

{
	MessageQueueBackend *mq_ptr;

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufMsgQueueSub", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	if (unlikely(ptr == NULL))	return NULL;

	mq_ptr=(MessageQueueBackend *)ptr;

	if ((_CreateMessageQueueTopics (mq_ptr, masterptr->main_listener_protoid)) != 0)	return(0);//exit thread

	while (1) {
		int x, read_len;
		fd_set fd,
				xfd;
		char msg[X11BUF];

		again:
		FD_ZERO(&fd);
		FD_ZERO(&xfd);

		FD_SET(((redisContext *)mq_ptr->persistance_agent)->fd, &fd);

		x = select(((redisContext *)mq_ptr->persistance_agent)->fd+1, &fd, NULL, NULL, NULL);

		if (x > 0) {
			read_len = read(((redisContext *)mq_ptr->persistance_agent)->fd, msg, X10BUF);
			if (read_len > 0) {
				msg[read_len-1] = 0;
				//syslog(LOG_ERR, "MessageQueueSub: received publish: '%s' length: '%d'", msg, read_len);
#if 0
				'*3/r/n $7/r/n message/r/n $13/r/n UFSRV:SESSION/r/n $2/r/n hi/r/n'
								1					2						3
#endif
				if (msg[0] == '*') {
					char *verb, *topic;
					char *aux,  *tmsg;
					size_t len = 0;

					aux = msg + 1;//skip past '*'
					*(aux + 1) = '\0'; //kill '/r' so atoi sees termination point for the digit, probably not necessary Assumes single digit
					int nargs = atoi(aux);
					aux += 4;//skip past \r\n$ assumes single digit argument, which is not unreasonable

					//7/r/n
						while(*aux != '\r') {
							len = (len * 10) + (*aux - '0');
							aux++;
						}

						aux += 2; //move past \n$
						verb = aux;
						*(verb + len) = 0; //kills \r
						//syslog(LOG_ERR, "MessageQueueSub:  length: '%d' verb: '%s'...", len, verb);
						aux = verb + (len + 3);
						len = 0;

						while(*aux != '\r') {
							len = (len * 10)+(*aux - '0');
							aux++;
						}
						aux += 2; //move past \n$
						topic = aux;
						*(topic + len) = 0;//kills \r

						//syslog(LOG_ERR, "MessageQueueSub: length: '%d' topic: '%s'...", len, topic);
						aux = topic + (len + 3);//at size marker
						len = 0;

						while(*aux != '\r') {
							len = (len*10) + (*aux - '0');
							aux++;
						}

						aux += 2; //move past '\n '
						tmsg = aux;
						*(tmsg + len) = 0;//kills '\r' <-- not necessary as we memcopy len_amount + 1 extra for null

						//if (nargs==3)
						{
							syslog(LOG_ERR, "%s {nargs:'%d', len:'%lu', verb:'%s', topic:'%s', message:'...'}", __func__, nargs, len, verb, topic);

              pthread_mutex_lock(&sessions_delegator_ptr->ufsrv_thread_pool.work_queue_mutex);

              QueueEntry *qe_ptr = NULL;
              qe_ptr = AddQueue(&(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_work_queue));//remember this is mutex protected

              unsigned char *payload = calloc(1, len + 1);//extra space for null because the buffer is multiplex between binary and text payloads
              memcpy(payload, tmsg, len);
              qe_ptr->whatever = InitialiseMessageQueueMsgPayload_m(subpub_verb, GetBroadcastDescriptorByName(topic), payload, len, DELEGTYPE_MSGQUEUE);

              pthread_cond_broadcast(&sessions_delegator_ptr->ufsrv_thread_pool.queue_not_empty_cond);
              pthread_mutex_unlock(&sessions_delegator_ptr->ufsrv_thread_pool.work_queue_mutex);
						}
					}
						//server_id:cmd_idx:arg1:arg2:arg3
			}
			else if (read_len == 0) {
				syslog(LOG_ERR, "%s: received '0' length message: CLIENT DISCONNECTED: RE ESTABLISHING CONNECTION", __func__);

				if (SetupMessageQueueSubscriber(1))	_CreateMessageQueueTopics (masterptr->msgqueue_sub, masterptr->main_listener_protoid);
			} else {

			}

		} else if (x == 0) {
      //timeout
		} else if (x == -1 && errno != EINTR) {
			syslog(LOG_ERR, "ThreadCommandConsoleClient: ERROR: select");

			//goto again;
		}

		//goto again;
	}

	return NULL;

}


static size_t _CalculateTopicsStringSize (CollectionDescriptor *collection_topics);

__pure static size_t
_CalculateTopicsStringSize (CollectionDescriptor *collection_topics)
{
	size_t total_sz=0;

	for (size_t i=0; i<collection_topics->collection_sz; i++)	total_sz+=strlen((const char *)collection_topics->collection[i]);

	return total_sz;
}

/**
 * @brief: the channels to which we listen for updates. Add new channels here. There is no interface to dynamically achieve that, so all calls
 * must be hard coded here in. Channels stay on for the lifetime of the server and are pretty much fixed per given protocol.
 *
 * As the parser above is under developed, any topic added here, must have a corresponding parser block in the the function ParseMessageQueueCommand().
 *
 */
static int
_CreateMessageQueueTopics (MessageQueueBackend *mq_ptr, unsigned protocol_id)
{
	extern const Protocol *const protocols_registry_ptr;
	UFSRVResult result={0};
#define REDIS_COMMAND_SUBSCRIBE "SUBSCRIBE "

	if 	(IS_EMPTY(_PROTOCOL_CLLBACKS_MSGQUEUE_TOPICS(protocols_registry_ptr, protocol_id)))									goto exit_msgqueue_disabled;
	if	(IS_EMPTY(_PROTOCOL_CLLBACKS_MSGQUEUE_TOPICS_INVOKE(protocols_registry_ptr, protocol_id, &result)))	goto exit_msgqueue_disabled;

	CollectionDescriptor *collection_topics=(CollectionDescriptor *)result.result_user_data;

	if (IS_PRESENT(collection_topics) && (collection_topics->collection_sz>0))
	{
		size_t topics_string_sz;
		if ((topics_string_sz=_CalculateTopicsStringSize(collection_topics))<=0)	goto exit_error;

		char 	topics_string[topics_string_sz+
												(collection_topics->collection_sz)+//nulls
												(sizeof(REDIS_COMMAND_SUBSCRIBE)*collection_topics->collection_sz)//this already contains nulls due sizeof
											 ];
		char *subscribe_commands[collection_topics->collection_sz];
		char	*walker			=	topics_string;


		for (size_t i=0; i<collection_topics->collection_sz; i++)
		{
			size_t topic_sz=strlen((const char *)collection_topics->collection[i]);
			sprintf (walker, REDIS_COMMAND_SUBSCRIBE "%s", (const char *)collection_topics->collection[i]);
			subscribe_commands[i]=walker;
			walker+=(topic_sz+sizeof(REDIS_COMMAND_SUBSCRIBE));//+1);//+1 skip over space
		}


		for (size_t i=0; i<collection_topics->collection_sz; i++)
		{
			redisReply *redis_ptr=(*mq_ptr->send_command)(mq_ptr, subscribe_commands[i]);

			if (IS_PRESENT(redis_ptr))
			{
				syslog(LOG_INFO, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

				freeReplyObject (redis_ptr);
			}
			else	goto exit_redis_error;
		}

		exit_success:
		return 0;

	}

	exit_msgqueue_disabled:
	syslog (LOG_WARNING, "%s (protocol_id:'%u'): MessageQueue Listener shutdown: Not supported by protocol", __func__, protocol_id);
	return 1;


	exit_error:
	return -1;

	exit_redis_error:
	syslog (LOG_WARNING, "%s (protocol_id:'%u'): MessageQueue Listener shutdown: COULDN'T ISSUE SUBSCRIBE COMMAND", __func__, protocol_id);
	return -2;

#if 0
	redisReply *redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE UFSRV:SESSION");
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE " _INTERCOMMAND_MSG);
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE UFSRV:FENCE");
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE UFSRV:INTRA:FENCE");
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE " _INTRACOMMAND_MSG);
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE " _INTRACOMMAND_USER);
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}

	redis_ptr=(*mq_ptr->send_command)(mq_ptr, "SUBSCRIBE " _INTRACOMMAND_SESSION);
	if (redis_ptr)
	{
		syslog(LOG_ERR, "%s: Subscribed to: '%s'. Total subscriptions for this instance: '%lld'", __func__, redis_ptr->element[1]->str, redis_ptr->element[2]->integer);

		freeReplyObject(redis_ptr);
	}
#endif
}

/*
 * @brief only one listener per usfrv instance
 */
void CreateMessageQueueSubscriberListenerThread(void)
{
	MessageQueueBackend *mq_ptr = SetupMessageQueueSubscriber (0);//returned value is also globally defined in masterptr->msgqueue_sub
	{

		syslog(LOG_INFO, ">> %s: Launching MessageQueue Subscriber Listener thread...", __func__);
		pthread_create (&th_msgqueue_sub, NULL, ThreadMessageQueueSub, mq_ptr);
	}

	//return nsocket;

}



