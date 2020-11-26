/**
 * Copyright (C) 2015-2020 unfacd works
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

#ifndef SRC_INCLUDE_SOCKET_MESSAGE_TYPE_H_
#define SRC_INCLUDE_SOCKET_MESSAGE_TYPE_H_

#include <standard_c_includes.h>

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
