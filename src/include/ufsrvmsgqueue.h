/*
 * persistance_type.h
 *
 *  Created on: 24 Jul 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UFSRVMSGQUEUE_H_
#define SRC_INCLUDE_UFSRVMSGQUEUE_H_

#include <ufsrvmsgqueue_type.h>
#include <ufsrvcmd_broadcast_type.h>

//#define _INTERCOMMAND_SESSION		"UFSRV:SESSION"
//#define _INTERCOMMAND_FENCE			"UFSRV:FENCE"
//#define _INTERCOMMAND_MSG				"UFSRV:MSG"
//#define _INTRACOMMAND_MSG				"UFSRV:INTRA:MSG"
//#define _INTRACOMMAND_FENCE			"UFSRV:INTRA:FENCE"
//#define _INTRACOMMAND_USER			"UFSRV:INTRA:USER"
//#define _INTRACOMMAND_SESSION		"UFSRV:INTRA:SESSION"

MessageQueueBackend *
InitialiseMessageQueueBackend (MessageQueueBackend *);
MessageQueueBackend *
SetupMessageQueueSubscriber (int);
//int ParseMessageQueueCommand (MessageQueueMsgPayload *);
void CreateMessageQueueSubscriberListenerThread (void);
//inline MessageQueueMsgPayload *
//InitialiseMessageQueueMsgPayload_m (const char *, const char *, const char *, unsigned);


/**
 * 	/brief arguments are assumed to be dynamically allocated by the calling environment.
 */
static inline MessageQueueMsgPayload *
InitialiseMessageQueueMsgPayload_m (char *verb, UfsrvCommandBroadcast *ufsrv_broadcast_ptr, unsigned char *payload, size_t payload_sz, unsigned delegator_type)

{
	MessageQueueMsgPayload *mqp_ptr;

	mqp_ptr=calloc(1, sizeof(MessageQueueMsgPayload));
	if (mqp_ptr)
	{
		mqp_ptr->verb=verb;
		mqp_ptr->topic=ufsrv_broadcast_ptr->topic_name;//topic;
		//mqp_ptr->msg=msg;
		mqp_ptr->payload=payload;
		mqp_ptr->payload_sz=payload_sz;
		mqp_ptr->delegator_type=delegator_type;

		return mqp_ptr;
	}

	return NULL;
}


static inline void
DestructMessageQueueMsgPayload (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, bool flag_self_destruct)
{
	if (likely(mqp_ptr!=NULL))
	{
		if (IS_PRESENT(mqm_ptr))	message_queue_message__free_unpacked(mqm_ptr, NULL);

		//if (mqp_ptr->msg)	free(mqp_ptr->msg);

		if (mqp_ptr->payload && mqp_ptr->payload_sz>0)	free (mqp_ptr->payload);

		if (flag_self_destruct)
		{
			free (mqp_ptr);
			mqp_ptr=NULL;
		}
	}
}

#endif /* SRC_INCLUDE_UFSRVMSGQUEUE_H_ */
