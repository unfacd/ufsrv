/*
 * socket_message_type.h
 *
 *  Created on: 28 Jul 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SOCKET_MESSAGE_TYPE_H_
#define SRC_INCLUDE_SOCKET_MESSAGE_TYPE_H_


//for practical reasosn we only allow for this amount of individual frames per SocketMessage
//each index is the offset into _processed_msg to retrieve payload length for each frame where frame >1
#define SOCKMSG_MAX_FRAME_COUNT	16


struct SocketMessage {
	 unsigned char *_raw_msg;
	 ssize_t raw_msg_size;

	 unsigned char *_processed_msg;
	 ssize_t processed_msg_size;

	 unsigned char *holding_buffer;//dynamic buffer to hold temporary frame fragment
	 ssize_t holding_buffer_msg_size;//needs to be joined with missing_msg_size

	 ssize_t written_msg_size;//how much was last written

	 ssize_t missing_msg_size;//amount of missing bytes in raw_msg buffer that need to be fetched upon next read
	 size_t frame_count;//how many frames are embedded in the processed_msg buffer
	 size_t raw_msg_cur_pos;//where current raw_buffer has fragment of a frame

	 //indexed per frame_count to retrieve individual frame payload length. Terminating with \0 doesnt work with binary data
	 size_t frame_index[SOCKMSG_MAX_FRAME_COUNT];
	 int sm_errno;
	 unsigned flag;
	 };
 typedef struct SocketMessage SocketMessage;


#endif /* SRC_INCLUDE_SOCKET_MESSAGE_TYPE_H_ */
