/*
 * message.h
 *
 *  Created on: 21 Mar 2015
 *      Author: ayman
 */


#ifndef INCLUDE_MESSAGE_TYPE_H_
#define INCLUDE_MESSAGE_TYPE_H_

//#include <fence_type.h>
//#include <users.h>

//operate on QueueEntry *
#define MESSAGE_IN_QUEUE(x) ((Message *)x->whatever)

	struct Message {
		unsigned attrs;
		char *msg;
		unsigned long msg_id;
		time_t when;
		unsigned long fence_id;
		unsigned long user_id;
		//Fence *f_ptr;
		//User *u_ptr;
	};
	typedef struct Message Message;


#endif /* SRC_INCLUDE_MESSAGE_H_ */
