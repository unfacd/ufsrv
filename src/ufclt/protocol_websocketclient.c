/*
 * protocol_websocketclient.c
 *
 *  Created on: 21 Jul 2016
 *      Author: ayman
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrvresult_type.h>
#include <ufsrvmsg_core/include/sockets.h>
#include <list.h>
#include <session.h>
#include <misc.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include <ufsrvmsg_core/protocol/protocol_io.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvwebsock/include/protocol_websocket_routines.h>
#include <ufsrvwebsock/include/protocol_websocket_io.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>
#include "protocol_websocketclient.h"

//extern  const  Protocol *const protocols_registry_ptr;



UFSRVResult *
proto_websocketclient_msg_callback(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned call_flags, size_t len)
{

	ssize_t read_result;

	read_result = ReadFromSocket(sesn_ptr, sock_msg_ptr, call_flags);

	if (read_result > 0)	goto process_framed_decoded_msg;
	else if (read_result == 0)//if we are reading a very large frame, the first fragment will be seen by decode_hybi, which will return 0
		//subsequent reads will detect missing size and will continue to report zero until  full frame is recieved up to 65k which is the max frame zize we allowe for Websocket
	{
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): COULD NOT FIND COMPLETE FRAME: NO MSG WILL BE PROCESSED: (frame_coundt='%lu' missing_msg_size: '%lu') RETURNING...",
				__func__, sesn_ptr->pid, SESSION_ID(sesn_ptr), sock_msg_ptr->frame_count, sock_msg_ptr->missing_msg_size);

		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION);
	}
	else
	{
		read_error:
		switch (read_result)
		{
		case -1:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);//suspended

		case -2:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK);

		case -3://user sent termination in WS
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_CONNECTIONCLOSED);

		case -4:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_DECODED);//this fatal couldent base64 decode: suspend

		case -5:
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MISSGINGFRAMEDATA);//benign error couldn't process frame because of incomplete frame data

		default:
			_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}
	}


	process_framed_decoded_msg:
	#if 1

	//TODO: this may be redundant as read_result==0 condition above should indicate the same cndition
	if (sock_msg_ptr->frame_count == 0)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO FRAME WAS FOUND: NO MSG WILL BE PROCESSED: (missing_msg_size: '%lu') RETURNING...",
			__func__, sesn_ptr->pid, SESSION_ID(sesn_ptr), sock_msg_ptr->missing_msg_size);

		//TODO: FIX: this should be considered an error condition?
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_FRAGMENTATION);
		//return sesn_ptr;
	}

	//start framed_decoded_msg
	{
		unsigned loop_counter = sock_msg_ptr->frame_count;
		const ProtocolCallbacks *const pc = &(((Protocol *)sesn_ptr->protocol_registry)->protocol_callbacks);
		//size_t len=sock_msg_ptr->frame_index[loop_counter-1];//length of the first frame payload
		size_t len       = sock_msg_ptr->frame_index[0];//length of the first frame payload
		int frame_offset = 0;
		//int ufcmd_result=0;
		UFSRVResult *ufcmd_result;
		extern UFSRVResult *ParseServerCommand(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len);

		while ((loop_counter--))
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): PARSE ITERATION: '%d': PAYLOAD length: '%lu' READING OFFSET '%d'...",
					__func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter + 1, len, frame_offset);

			ufcmd_result = ParseServerCommand(sesn_ptr, sock_msg_ptr, frame_offset, len);

			switch (ufcmd_result->result_type)
			{
			case RESULT_TYPE_SUCCESS:
				if (ufcmd_result->result_code == RESCODE_IO_MSGPARSED)//(ufcmd_result>0)
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESSFULLY INVOKED MSG CALLBACK...", __func__, pthread_self(), SESSION_ID(sesn_ptr));
				}
			break;

			case RESULT_TYPE_ERR:
				switch (ufcmd_result->result_code)
				{
					case RESCODE_IO_MSGPARSED:
						//processing or logical error
						syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'):  COULD NOT parse message...", __func__, pthread_self(), SESSION_ID(sesn_ptr));

						//TODO: implement trip threshold
						//ignore requestand send error status back to client
					break;	//to loop_processing_body

					case RESCODE_LOGIC_NOCMND:
						syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'):  COULD NOT parse message: NO COMMAND FOUND", __func__, pthread_self(), SESSION_ID(sesn_ptr));
					break;

					default:
						//network error
						if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED))
						{
							syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SESSION HAS BEEN SUSPENDED AMID ITERATION: PARSE ITERATION: '%d': READING OFFSET '%d': DISCONTINUING LOOP",
								__func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter+1, frame_offset);

							//TODO: do we break? or save the frame_offset where we left?we need to retry last msg?
						}
				}//inner switch
			break;//RESULT_TYPE_ERR

			}//outer switch

			loop_processing_body:
			//additional check just in case
			if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): OUTSIDE CONDITIONAL: SESSION HAS BEEN SUSPENDED AMID ITERATION: PARSE ITERATION: '%d': READING OFFSET '%d'...",
					__func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter+1, frame_offset);

				//TODO: do we break? or save the frame_offset where we left?we need to retry last msg?
				break;
			}

			if (loop_counter)
			{//only do it if loop_counter is >0 ie we have a subsequent run
				frame_offset += len;//remember last len

				if (frame_offset == sock_msg_ptr->processed_msg_size)
				{
					syslog(LOG_DEBUG, ">>>> %s (pid:'%lu' cid:'%lu'): MESG OFFSET EQUALS TOTAL MSG SIZE: loop_counter: '%u'. frame_offset='%d'. BREAKING LOOP",
						__func__, pthread_self(), SESSION_ID(sesn_ptr), loop_counter + 1, frame_offset);
					break;
				}
				len = sock_msg_ptr->frame_index[sock_msg_ptr->frame_count - (loop_counter - 1)];//Increment offset to go past the '0'then read the length upto the next '0'
			}

		}//while

		//reset buffer
		cleanup_exit_block:
		free(sock_msg_ptr->_processed_msg);
		sock_msg_ptr->_processed_msg = 0;
		sock_msg_ptr->processed_msg_size = 0;

		//return sesn_ptr;
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED);

	}//end framed_decoded_msg


	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);


	#endif
}


UFSRVResult *
proto_websocketclient_decode_msg_callback (Session *sesn_ptr, SocketMessage *sm_ptr, unsigned frame_offset)
{
	unsigned int opcode=0, left;

	sm_ptr->_processed_msg=calloc(1, sm_ptr->raw_msg_size);

	//this will tokenise multiple frames on '\0'
	//>>>>>>>>>>>>>>>>>>>>>>>>
	sm_ptr->processed_msg_size=decode_hybi_client(sm_ptr, sm_ptr->_raw_msg, sm_ptr->raw_msg_size, sm_ptr->_processed_msg, sm_ptr->raw_msg_size, &opcode, &left);
	//>>>>>>>>>>>>>>>>>>>>>>>>

	if (opcode==8)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): client sent orderly close frame", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));

		//all allocated buffers are cleared
		SuspendSession (sesn_ptr, 0);//hard suspend in main loop only

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_PROTOCOL_SHUTDOWN);
		//return -3;//user induced termination
	}

	if (sm_ptr->processed_msg_size<0)
	{
		decoding_error:
		syslog(LOG_ERR, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT DECODE MESSAGE. SocketMessage will be destructed. Connection  will be suspended",
			__func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));

		//buffer data is now unbalanced: get rid of it now in case the client becomes unsuspended and uses the buffer again
		//TODO: check for sock-msg type? not dynamic
		DestructSocketMessage (sm_ptr); //this will free sm_ptr->_processed_msg even if its corresponding size is -1

		SuspendSession (sesn_ptr, 0);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_DECODED);
		//return -4; //TODO: consider error handling outside this function

	}//if len<0

	//we have incomplete frame. cur_pos point to the begining of the incomplete frame in _processed_msg
	if (sm_ptr->missing_msg_size)
	{
		//tin_start = tin_end - sm_ptr->missing_msg_size;

		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): PARTIAL FRAME from client: amount left to be read: '%ld'. raw_msg_cur_pos='%ld'. holding_buffer_msg_size: '%ld' (This amount will be copied into holding_buffer). Raw buffer will be freed.",
				__func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sm_ptr->raw_msg_cur_pos, sm_ptr->holding_buffer_msg_size);

		//how much we managed to collect so far
		sm_ptr->holding_buffer=mystrndup(sm_ptr->_raw_msg+sm_ptr->raw_msg_cur_pos, sm_ptr->holding_buffer_msg_size);
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCESS: READ AND DECODED MESSAGE. size:  '%ld'. Raw buffer will be freed.",
			__func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), sm_ptr->processed_msg_size);
		//tin_start = 0;//finished processing
		//tin_end = 0;
	}


	//we are good. This buffer has been successfully utilised wholly or in part
	free (sm_ptr->_raw_msg);
	sm_ptr->_raw_msg=0;
	sm_ptr->raw_msg_size=0;///

	_RETURN_RESULT_SESN(sesn_ptr, sm_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_DECODED);
	//return sm_ptr->processed_msg_size;

}



UFSRVResult *
proto_websocketclient_encode_msg_callback (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset)
{

	///*sptr->msg_out_len*/sesnptr->ssptr->socket_msg.processed_msg_size=encode_hybi(sptr->msg, sptr->msglen, sptr->msg_out2, XLARGBUF, 1);
	sesn_ptr->ssptr->socket_msg_out.processed_msg_size=encode_hybi_client(&(sesn_ptr->ssptr->socket_msg_out),
	sesn_ptr->ssptr->socket_msg_out._raw_msg, sesn_ptr->ssptr->socket_msg_out.raw_msg_size,
	sesn_ptr->ssptr->socket_msg_out._processed_msg, sesn_ptr->ssptr->socket_msg_out.processed_msg_size, 2);//binary not text 1);

	/*
	 * Two possibilities:
	 * for straight-through both raw and processed are the same reference: so we can free processed and zero out
	 * For WebSocket: raw and processed are both allocated so both must be freed
	 * However, this block is concerned with Websocket condition only
	 */
	if (sesn_ptr->ssptr->socket_msg_out.processed_msg_size<0)
	{
		syslog(LOG_NOTICE, "%s: (pid:'%lu' cid:'%lu'): ERROR: COULD NOT ENCODE MSG...", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));

		//this is done in the caling environment based in return value
		//DestructSocketMessage (&(sesn_ptr->ssptr->socket_msg_out));
		/*
		free (sesn_ptr->ssptr->socket_msg_out._processed_msg);
		sesn_ptr->ssptr->socket_msg_out.processed_msg_size=0;


		//this is not relevant for WebSocket causes leak
		//free because raw is is already loaded
		//if (msg)
		{
			free(sesn_ptr->ssptr->socket_msg_out._raw_msg);
			sesn_ptr->ssptr->socket_msg_out.raw_msg_size=0;
		}
		 */
		//error
		//return -3;//0;
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_IO_ENCODED);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_ENCODED);

}
