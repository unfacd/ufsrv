/*
 * persistance_type.h
 *
 *  Created on: 24 Jul 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_UFSRVMSGQUEUE_TYPE_H_
#define SRC_INCLUDE_UFSRVMSGQUEUE_TYPE_H_

typedef struct MessageQueueBackend MessageQueueBackend;
	struct MessageQueueBackend	{
		void *persistance_agent;//redisConetx *
		void *(*send_command)();//TODO CONVERT TO REGULAR BACKEND
		void *(*send_command_multi)();//pipelined synchronous redis command
		MessageQueueBackend *(*init_connection)(MessageQueueBackend *);
	};

	/**
	 * 	/brief carrier message to exchange recieved message with MsgQueue parser
	 */
	struct MessageQueueMsgPayload {
		char *verb;
		char *topic;
		//char *msg;
		unsigned char *payload;//in instances where msg is not self sufficient, payload can contain request specific data
		size_t payload_sz;
		unsigned delegator_type;
		int (*work_exec)();
	};
typedef struct MessageQueueMsgPayload MessageQueueMsgPayload;

#endif /* SRC_INCLUDE_UFSRVMSGQUEUE_TYPE_H_ */
