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

#include <math.h>
#include <main.h>
#include <misc.h>
#include <recycler.h>
#include <ufsrvresult_type.h>
#include <sockets.h>
#include <nportredird.h>
#include <protocol.h>
#include <protocol_io.h>
#include <protocol_websocket_routines.h>
#include <instrumentation_backend.h>
#include <delegator_session_worker_thread.h>

extern ufsrv *const masterptr;
extern  const  Protocol *const protocols_registry_ptr;

inline static ssize_t
_SendToSocket (Session *sesn_ptr, SocketMessage *sock_msg_ptr, const char *msg, unsigned flag);
inline static ssize_t
_DispatchSocketBuffer (Session *sesn_ptr, SocketMessage *sock_msg_ptr);
static int
_SocketMessageDecode (Session *sesn_ptr, SocketMessage *sm_ptr, unsigned flag);
static int
_SocketMessageEncode (Session *sesn_ptr, SocketMessage *sm_ptr, unsigned flag);

/**
 * 	@brief: this reads/queues into Sessions incoming SocketMessage. It operates under the assumption that reader does not own Session lock.
 * 	Since we own MessageQueue lock, we are assured no concurrent read of the socket can take place, or read into transitional incoming buffer
 * 	@param blocksz: Since we don't own the session, we need to know current session's read-block size
 * 	@locked: MessageQueue must be locked
 * 	@dynamic_memory:	allocates a 'SocketMesage *' which if successful freed somehwrere else
 * 	@return: >0 amount of bytes read, 0 would block, -1 io error
 */
inline static ssize_t
_ReadIntoMessageQueueWithNoSessionLock (Session *sesn_ptr, int blocksz)
{
	char erbuf[MBUF] = {0};
	char *er;
	bool blocking_io = false;
	SocketMessage *sm_ptr = calloc(1, sizeof(SocketMessage));

	//allocate buffer
	sm_ptr->_raw_msg = calloc(1, blocksz);

	//this bit is immutable so it maybe safe to read concurrently
	if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE)) {
		ERR_clear_error();
		sm_ptr->raw_msg_size = SSL_read(sesn_ptr->session_crypto.ssl, sm_ptr->_raw_msg, blocksz);
	} else {
		sm_ptr->raw_msg_size = read(sesn_ptr->ssptr->sock, sm_ptr->_raw_msg, blocksz);
	}

	sm_ptr->sm_errno = errno;

	if (sm_ptr->raw_msg_size > 0) {
		sm_ptr->sm_errno = 0;//set it to sane value

		AddToQueue(&(sesn_ptr->message_queue_in.queue), sm_ptr);

		syslog(LOG_DEBUG, LOGSTR_IO_MSGQ_ADD_NODECODE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr), sm_ptr->raw_msg_size, sm_ptr->missing_msg_size, SESSION_CUMMULATIVE_RC(sesn_ptr), LOGCODE_IO_MSGQ_ADD_NODECODE);

		return sm_ptr->raw_msg_size;
	} else {
		//ascertain blocking socket status
		if (sm_ptr->raw_msg_size == -1) {
			if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE)) {
				//errors other than blocking related https://www.openssl.org/docs/manmaster/ssl/SSL_get_error.html
				int err = SSL_get_error(sesn_ptr->session_crypto.ssl, sm_ptr->raw_msg_size);
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {//open SSL can return either during read
					blocking_io = true;
				}
			} else if ((sm_ptr->sm_errno == EAGAIN) || (sm_ptr->sm_errno == EWOULDBLOCK)) {// || (sm_ptr->sm_errno==EINPROGRESS)
				  blocking_io = true;
      }

			if (blocking_io) {
				//nothing we can do we just go back status quo unchanged
				syslog(LOG_NOTICE, LOGSTR_IO_BLOCKING_READ, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->sm_errno, LOGCODE_IO_BLOCKING_READ_NO_SESNLOCK);

				free (sm_ptr->_raw_msg);
				free(sm_ptr);

				return 0;
			} else {
				goto error_io;
			}
		} else {
			//we read 0
			error_io:
			er = strerror_r (sm_ptr->sm_errno, erbuf, MBUF);

			//since we don't own the Session's lock, well queue it in as an error exception, to alert at qeue consolidation time
			AddToQueue(&(sesn_ptr->message_queue_in.queue), sm_ptr);

			syslog(LOG_DEBUG, LOGSTR_QUEING_EXCEPTION, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr), sm_ptr->sm_errno, er, LOGCODE_IO_QUEINGEXC);

			//since we read nothing anyway,  we deallocate
			free (sm_ptr->_raw_msg);
			sm_ptr->raw_msg_size = 0;

			return -1;
		}
	}

}

/**
 *

//
//	@brief	Assumes nonblocking. Should only be used with fully connected session.
//	@brief	The processed buffer can contain more than one frame. Incomplete frame in stored separately in a holding buffer.
//	Can read concurrently into a queued input buffer, where the session lock is own by other thread. To achieve that, pass the following:
//	ReadFromSocket(sesnptr, NULL, SOCKMSG_READSOCKET|SOCKMSG_DONTDECODE|SOCKMSG_DONTOWNSESNLOCK);
//	@param	sock_msg_ptr if NULL 1)create a SocketMessage and attach to incoming SocketMessage 2)used passed buffer
// 	@param	flag=SOCKMSG_READBUFFER the messge is being read from SocketMessage. The queue should be locked in  the calling function
//	@param	flag=SOCKMSG_READSOCKET the message is read from network socket.If @aparam sock_msg_ptr is null, store the message in the incoming message queue
//	@param	flag=SOCKMSG_DONTDECODE message is stored raw. combined with SOCKMSG_READSOCKET (sock_msg_ptr must be NULL) has the effect of enqueueing the message without any processing.
//			this is used when the caller doesn't own the Session lock, so we just read into the Socket's incoming queue.
//	@param	flag=SOCKMSG_DONTOWNSESNLOCK indicates the current thread does not own the lock for the Session, so we are limited to only enqueueing locally created SocketMessageQueue
//			 which must be locked separately to acghieve that effect.
//	@param flag=SOCKMSG_KEEPMSGQUEUE_LOCKED: only applicable if we are reading into the queue
//
//	@locks	Session.MessageQueueIncoming
//	@side-effect	Session object suspended where it is caused by i/o events
// 	sm_ptr->holding_buffer maybe created
 //	@return -2 logical error
// 	@return	-1 socket errot. 0 on protocol close. amount of bytes read if >0
 //	@return 0	amended buffer with more data, but still not complete to process OR blocking read
//
*/
ssize_t
ReadFromSocket (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned flag)
{
	int 		no_error=1;
	int 		i;
	bool 		blocking_io=false;
	ssize_t raw_msg_size;

	//for strerror()
	char erbuf[MBUF] = {0};
	char *er = NULL;
	SocketMessage *sm_ptr = NULL;

	if (sock_msg_ptr) {
		sm_ptr=sock_msg_ptr;
	} else {

	}

	if (flag&SOCKMSG_READSOCKET) {
		UFSRVResult res;
		SocketMessage *sm_ptr_consolidated = NULL;

		//this lock ensures one thread at a time reads the socket, but multiple threads can queue for it
		if ((MessageQueueLock(sesn_ptr, SESSION_INSOCKMSG_PTR(sesn_ptr), 0)) != 0) {
			return -2;//nothing we can do we just go back
		}

		if (!sock_msg_ptr) {
			ssize_t rc = _ReadIntoMessageQueueWithNoSessionLock(sesn_ptr, SESSION_SOCKETBLOCKSZ(sesn_ptr));

			if (!(flag&SOCKMSG_KEEPMSGQUEUE_LOCKED))	MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

			return rc;
		}

		//>>> MessageQueue Locked, Session Locked

		//consolidate into transitional buffer
		ConsolidateSocketMessageQueue(sesn_ptr, SOCKMSG_CONSOLIDATE_INSESSION, &res);//function should not lock queue in absence of flag
		if (res.result_type == RESULT_TYPE_SUCCESS) {
			//this is the regular transitional buffer: we could have read it directly off sesn_ptr
			sm_ptr_consolidated = (SocketMessage *)res.result_user_data;

			//check for previously flagged I/O error
			if (!(sm_ptr_consolidated->sm_errno == 0)) {
				syslog(LOG_DEBUG, LOGSTR_QUEDIOERR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr_consolidated->sm_errno, LOGCODE_TSWORKER_QUEUEDIOERR, "PRE REQUEST SERVICE");

				error_consolidation:
				ErrorFromSocket (InstanceHolderFromClientContext(sesn_ptr), CALLFLAGS_EMPTY);//don't consolidate queue, as we are not passing SOCKMSG_CONSOLIDATE_INSESSION

				//note flag&SOCKMSG_KEEPMSGQUEUE_LOCKED only honoured for in queueing mode
				MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

				return -1;
			}

			//we are good to continue below
		} else if ((res.result_type == RESULT_TYPE_ERR) && (res.result_code!=RESCODE_LOGIC_EMPTY_RESOURCE)) {
			//too bad we just bailout the session
			syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATION_ERR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_IO_BUF_CONSOLIDATION_ERR);

			goto error_consolidation;//same fate as above
		}
		//end consolidate_msgqueue_pre

    if (sm_ptr->raw_msg_size > 0) {
      //consolidation yielded some message: enlarge raw_msg by block_size so we can append new bytes into it (on success)
      unsigned char *tmp_hb = NULL;
      if (!(tmp_hb = realloc(sm_ptr->_raw_msg, sm_ptr->raw_msg_size+SESSION_SOCKETBLOCKSZ(sesn_ptr)))) {
        MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

        return -1;
      }

      //peg the read position of the raw buffer
      sm_ptr->raw_msg_cur_pos = sm_ptr->raw_msg_size;
      //re-point to the newly expanded buffer
      sm_ptr->_raw_msg = tmp_hb;
    } else {
      //perhaps queue was empty, we just allocate new buffer and set sane opening position
      sm_ptr->_raw_msg = calloc(1, SESSION_SOCKETBLOCKSZ(sesn_ptr));
      sm_ptr->raw_msg_cur_pos = 0;
      sm_ptr->raw_msg_size = 0;
    }

		//TODO: atomically check for SESNSTATUS_IOERROR efore reading as it could be set by another thread

		//this bit is immutable so it maybe safe to read concurrently
		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE)) {
			ERR_clear_error();
			raw_msg_size = SSL_read(sesn_ptr->session_crypto.ssl, sm_ptr->_raw_msg+sm_ptr->raw_msg_cur_pos, SESSION_SOCKETBLOCKSZ(sesn_ptr));
		} else {
			//this is not correct as thread may not hold Session mutex for this
			if (false) {//SESSION_SOCKETFD(sesn_ptr)<0)
				syslog(LOG_NOTICE, LOGSTR_IO_INVALID_READ_FD,
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr),
					sm_ptr->missing_msg_size, sm_ptr->raw_msg_size, sm_ptr->holding_buffer_msg_size, SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)?1:0, LOGCODE_IO_INVALID_READ_FD);
			}
			//

			raw_msg_size = read(sesn_ptr->ssptr->sock, sm_ptr->_raw_msg + sm_ptr->raw_msg_cur_pos, SESSION_SOCKETBLOCKSZ(sesn_ptr));
		}

		sm_ptr->sm_errno = errno;

		if (raw_msg_size == -1) {
			if (unlikely(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE))) {
				//errors other than blocking related https://www.openssl.org/docs/manmaster/ssl/SSL_get_error.html
				int err = SSL_get_error(sesn_ptr->session_crypto.ssl, raw_msg_size);
				sm_ptr->sm_errno = err;//we'll reuse it even though technically tis is not system errno
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
				  //open SSL can return either during read
					blocking_io = true;
				}
			} else if ((sm_ptr->sm_errno == EAGAIN) || (sm_ptr->sm_errno == EWOULDBLOCK) || (sm_ptr->sm_errno == EINPROGRESS)) {
				blocking_io = true;
			}
		}
		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


		if (raw_msg_size > 0) {
			//we read extra bytes so update total buffer size
			sm_ptr->raw_msg_cur_pos += raw_msg_size;//not sure I need this
			sm_ptr->raw_msg_size    += raw_msg_size;

			SESSION_INCREMENT_RC(sesn_ptr, raw_msg_size);

			//This block is not relevant if we are reading into MessageSocket queue, because SocketMessage is instantiated here so missing size is 0
			//previous msg contained incomplete frame
			if (sm_ptr->missing_msg_size > 0) {
				//what we received doesn't represent the entire length of the missing frame fragment, because the amount we read is not enough
				//this could be caused by the limited 'buffer size' passed to 'read()', or network issues: so we need another read
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NOTICE: SocketMessage contains missing buffer: missing_msg_size='%lu'. Read: raw_msg_size='%lu'. holding_buffer_msg_size='%lu'...",
					__func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sm_ptr->raw_msg_size, sm_ptr->holding_buffer_msg_size);

				if (sm_ptr->raw_msg_size < SESSION_SOCKETBLOCKSZ(sesn_ptr)) {
					//tweak back
					SESSION_SOCKETBLOCKSZ(sesn_ptr) = masterptr->buffer_size;//TODO: this is not entirely correct use the protocol's value
				}

				//this block terminates
				if (sm_ptr->raw_msg_size < sm_ptr->missing_msg_size) {
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): Received '%ld' bytes, but I need '%ld' bytes: growing holding_buffer to new size: '%ld'",
						__func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->raw_msg_size, sm_ptr->missing_msg_size, sm_ptr->holding_buffer_msg_size+sm_ptr->raw_msg_size);

					//enlarge the holding buffer, copy new bytes and adjust length, and return
					unsigned char *tmp_hb = realloc(sm_ptr->holding_buffer, sm_ptr->holding_buffer_msg_size+sm_ptr->raw_msg_size);
					if (!tmp_hb) {
						//memory allocation error: clean up
						free (sm_ptr->_raw_msg);
						sm_ptr->raw_msg_size  = 0;
						sm_ptr->sm_errno      = 0;

						if (!(sock_msg_ptr)) {
							free (sm_ptr);
						}

						MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

						return -2;
					}

					success_need_more:
					sm_ptr->holding_buffer = tmp_hb;
					memcpy (sm_ptr->holding_buffer + sm_ptr->holding_buffer_msg_size, sm_ptr->_raw_msg, sm_ptr->raw_msg_size);
					sm_ptr->holding_buffer_msg_size += sm_ptr->raw_msg_size;
					sm_ptr->missing_msg_size -= sm_ptr->raw_msg_size;

					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): APPENDED frame fragment: holding_buffer_msg_size='%ld'. Missing: '%ld'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->holding_buffer_msg_size, sm_ptr->missing_msg_size);

					free (sm_ptr->_raw_msg);
					sm_ptr->raw_msg_size  = 0;
					sm_ptr->sm_errno      = 0;

					MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

					//we still need to read more
					return 0;
				}

				//OK we read as much into _raw_msg, or more than what was previously missing. Do the following steps:

				//1)enlarge holding buffer by additional raw_msg_size factor
				unsigned char *tmp_hb = NULL;
				if (!(tmp_hb = realloc(sm_ptr->holding_buffer, sm_ptr->holding_buffer_msg_size+sm_ptr->raw_msg_size + 10)))//extra space for holding separating '\0' n where we have multiple frames in one buffer
				{
					//memory allocation error: clean up
					free (sm_ptr->_raw_msg);
					sm_ptr->raw_msg_size = 0;
					sm_ptr->sm_errno     = 0;

					if (!sock_msg_ptr)	free (sm_ptr);

					MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

					return -1;
				}

				sm_ptr->holding_buffer = tmp_hb;

				//2)append new frame fragment
				memcpy (sm_ptr->holding_buffer + sm_ptr->holding_buffer_msg_size, sm_ptr->_raw_msg, sm_ptr->raw_msg_size);

				//3)update actual length to reflect joined frame
				sm_ptr->raw_msg_size += sm_ptr->holding_buffer_msg_size;
				//tin_end+=sm_ptr->raw_msg_size;

				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): JOINED FRAME FRAGMENTS: new msg size: '%lu' ", __func__, pthread_self(), SESSION_ID(sesn_ptr),
						sm_ptr->raw_msg_size);

				//4)free fragment and repoint it to full frame
				free(sm_ptr->_raw_msg);
				sm_ptr->_raw_msg = sm_ptr->holding_buffer;

				//reset
				sm_ptr->holding_buffer = NULL;
				sm_ptr->holding_buffer_msg_size = sm_ptr->missing_msg_size = 0;
				sm_ptr->sm_errno = 0;
				//we are now ready to feed joined frame into decode and determine if we have a complete frame
			} else {
				//do nothing we read postive number of bytes
			}
		} else {//we read <=0
		//if 	(raw_msg_size<=0)
			if (raw_msg_size == -1) {
				if (blocking_io) {
					if (sm_ptr->raw_msg_size == 0) {//this is the consolidated SocketMessage
						//nothing we can do: unwind allocation (implies consolidation yielded none)
						syslog(LOG_NOTICE, LOGSTR_IO_BLOCKING_READ, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->sm_errno, LOGCODE_IO_BLOCKING);

						free (sm_ptr->_raw_msg);

						sm_ptr->sm_errno = 0;

						MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

						//we preserve state of existing buffer data
						return 0;
					}

					__blocked_read_but_have_consolidated_buffer:

					//perhaps a unique case... we'll have a go at what we consolidated earlier so continue below to decoding
					syslog(LOG_NOTICE, LOGSTR_IO_BLOCKING_READ_WITH_RAW, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->sm_errno, sm_ptr->raw_msg_size, LOGCODE_IO_BLOCKING_READ_WITH_RAW);
				} else {
					//ordinary i/o error
					goto io_error;
				}
			} else {
			  //we read'0'
				io_error:

				if (unlikely(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE))) {
					int err = SSL_get_error(sesn_ptr->session_crypto.ssl, raw_msg_size);
					er = ERR_error_string(sm_ptr->sm_errno, NULL);
					switch (err)
					{
						case SSL_ERROR_NONE:
						{
							// no real error, just try again...
							printf("SSL_ERROR_NONE (%d)(%s)\n", err, er);
							break;
						}

						case SSL_ERROR_WANT_READ:
							printf("SSL_ERROR_WANT_READ (%d)(%s)\n", err, er);
							break;

						case SSL_ERROR_WANT_WRITE:
						{
							// socket not writable right now, wait a few seconds and try again...
							printf("SSL_ERROR_WANT_WRITE (%d)(%s)\n", err, er);
							break;
						}

						case SSL_ERROR_ZERO_RETURN:
						{

							printf("SSL_ERROR_ZERO_RETURN (%d)(%s): The TLS/SSL connection has been closed (peer disconnected?).\n", err, er);
							break;
						}

						case SSL_ERROR_SYSCALL:
						{
							printf("SSL_ERROR_SYSCALL (%d)(%s): Some I/O error occurred \n", err, er);
							int last_err = ERR_peek_last_error();
							er = ERR_error_string(last_err, NULL);
							printf("SSL_ERROR_SYSCALL (%d)(%s): Last error in the queue \n", last_err, er);
							break;
						}

						case SSL_ERROR_SSL:
						{

							printf("SSL_ERROR_SSL (%d)(%s): A failure in the SSL library occurred, usually a protocol error.\n", err, er);
							break;
						}

						default:
						{
							printf("UNOWN SSL ERROR (%d)(%s)\n", err, er);
							break;
						}

					}//switch
				} else {
					//er=strerror_r (sm_ptr->sm_errno, erbuf, MBUF);
				}

				//since we read nothing anyway,  we deallocate
				if (sm_ptr->raw_msg_size == 0) {
				  //this is the consolidated SocketMessage
#ifdef __UF_FULLDEBUG
					syslog(LOG_NOTICE, LOGSTR_IO_ERROR_READ_ZERO_EMPTY, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->raw_msg_size, LOGCODE_IO_ZERO_READ_WITH_RAW_EMPTY);
#endif
					free (sm_ptr->_raw_msg);
					//sm_ptr->raw_msg_size=0;

					//no consolidation: IMPOSSIBLE for other threads to have read anything, because we hold the queue lock, plus the socket erred
					ErrorFromSocket(InstanceHolderFromClientContext(sesn_ptr), 0);

					MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

					return -1;
				}

				//OK this is interesting, as we have some data to process "offline"
				//logically, same outcome as above, but I'll keep them on separate paths for now to explore "offline"
				syslog(LOG_NOTICE, LOGSTR_IO_ERROR_READ_ZERO, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->raw_msg_size, LOGCODE_IO_ERROR_READ_WITH_RAW);

				ErrorFromSocket(InstanceHolderFromClientContext(sesn_ptr), 0);

				MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

				return -1;

			}//read=0
		}//<=0

		//>>> WE READ POSITIVE AMOUNT OF BYTES
		//>>> LOCK IS STILL IN PLACE ON INCOMING QUEUE

		if ((sm_ptr->raw_msg_size >= SESSION_SOCKETBLOCKSZ(sesn_ptr))) {
		  // using '>=' since consolidation will inflate size so we cant just do '=='
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLEREQUEST);

			//ramp up capacity
			if (SESSION_SOCKETBLOCKSZ(sesn_ptr)<_CONF_READ_MAXBLOCKSZ(masterptr)) {
			  //1mb or whatever defined in the config file
				SESSION_SOCKETBLOCKSZ(sesn_ptr) *= 2;//double capacity
				if	(SESSION_SOCKETBLOCKSZ(sesn_ptr) > _CONF_READ_MAXBLOCKSZ(masterptr))	SESSION_SOCKETBLOCKSZ(sesn_ptr) = _CONF_READ_MAXBLOCKSZ(masterptr);
			}
		}

		MessageQueueUnLock(sesn_ptr, &(sesn_ptr->message_queue_in));

		if (flag&SOCKMSG_DONTDECODE)	return sm_ptr->raw_msg_size;

		//CONTINUE BELOW TO DECODING

	} else if (flag&SOCKMSG_READBUFFER) {
	  //we are reading from an already given buffer
		//>>>>> IMPORTANT: SocketMessage queue MUST BE locked in calling function

		if (flag&SOCKMSG_READQUEUE) {
			UFSRVResult res;

			//TODO: error checking
			ConsolidateSocketMessageQueue (sesn_ptr, SOCKMSG_CONSOLIDATE_INSESSION, &res);//dequeues into transient buffer
			sm_ptr = (SocketMessage *)res.result_user_data;

			//continue to start_msg_decoding;
			goto start_msg_decoding;
		}

		syslog(LOG_DEBUG, LOGSTR_IO_READING_MSGQUE_BUF, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sesn_ptr->message_queue_in.queue.nEntries, LOGCODE_IO_READING_MSGQUE_BUF);

		if ((sm_ptr->missing_msg_size > 0) && (sesn_ptr->message_queue_in.queue.nEntries == 0)) {
		  //we are not ready to process frame
			syslog(LOG_NOTICE, LOGSTR_IO_READ_MSGQUE_BUF_QUEEMPTY, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sesn_ptr->message_queue_in.queue.nEntries, LOGCODE_IO_READ_MSGQUE_BUF_QUEEMPTY);

			//NO RECOVERY..

			return -5;
		} else if ((sm_ptr->missing_msg_size > 0) && (sesn_ptr->message_queue_in.queue.nEntries > 0)) {
			syslog(LOG_NOTICE, LOGSTR_IO_READ_MSGQUE_NOTCONSOLIDATED, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->missing_msg_size, sesn_ptr->message_queue_in.queue.nEntries, LOGCODE_IO_READ_MSGQUE_NOTCONSOLIDATED);

			//TODO: do we force consolidation?
			//continue with decoding for now
			goto start_msg_decoding;
		}
//		else
//		if (flag&SOCKMSG_READQUEUE)
//		{
//			UFSRVResult res;
//			ConsolidateSocketMessageQueue (sesn_ptr, 0, &res);
//			sm_ptr=(SocketMessage *)res.result_user_data;
//			//continue to start_msg_decoding;
//		}

		//now branches to 'goto start_msg_decoding';
	} else {
		//>>> SocketMessage is not locked in this context
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): UNKNOWN MSG SOURCE...", __func__, pthread_self(), SESSION_ID(sesn_ptr));

		return -9;//some logical error
	}

	//past this point we have two possibilities:
	//1)sm_ptr represents a buffer read from the network
	//2)sm_ptr buffer supplied by the caller.

	//past this point queue should be unlocked if we are reading from socket, allowing other threads to read off socket
	start_msg_decoding:

	return (_SocketMessageDecode(sesn_ptr, sm_ptr, flag));

}


static int _SocketMessageDecode (Session *sesn_ptr, SocketMessage *sm_ptr, unsigned flag)
{
	if (_PROTOCOL_CLLBACKS_DECODE_MSG(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		if (flag&SOCKMSG_DONTDECODE) {
			//well, do nothing, shuffle pointers around. potentially useless case
			goto default_decode_block;
		}

		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_DECODE_MSG_INVOKE(protocols_registry_ptr,
												PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
												sesn_ptr, sm_ptr, flag);
		if (res_ptr->result_type == RESULT_TYPE_SUCCESS) {
			return sm_ptr->processed_msg_size;
		} else {
			switch (res_ptr->result_code)
			{
			case RESCODE_IO_DECODED:
				return -4;

			case RESCODE_IO_SUSPENDED:
				return -1;

			case RESCODE_IO_PROTOCOL_SHUTDOWN:
				return -3;
			}
		}
	} else {
		default_decode_block:
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): INVOKING _DEFAULT_ DECODE BLOCK: on raw_msg_size: '%ld' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->raw_msg_size);
#endif

		//just shift content across different buckets
		sm_ptr->_processed_msg = sm_ptr->_raw_msg;
		sm_ptr->processed_msg_size = sm_ptr->raw_msg_size;//=0;

		sm_ptr->raw_msg_size = 0;// prevents raw_msg from inadvertently free'd

		sm_ptr->sm_errno = 0;

		return sm_ptr->processed_msg_size;
	}

	return 0;

}

static int _SocketMessageEncode (Session *sesn_ptr, SocketMessage *sm_ptr, unsigned flag)
{
	if (_PROTOCOL_CLLBACKS_ENCODE_MSG(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
	{
		if (flag&SOCKMSG_DONTDECODE)
		{
			//well, do nothing, shuffle pointers around. potentially useless case
			goto default_encode_block;
		}

		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_ENCODE_MSG_INVOKE(protocols_registry_ptr,
												PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
												sesn_ptr, sm_ptr, flag);
		if (res_ptr->result_type==RESULT_TYPE_SUCCESS)
		{
			return sm_ptr->processed_msg_size;
		}
		else
		{
			switch (res_ptr->result_code)
			{
			case RESCODE_IO_DECODED:
				return -4;

			case RESCODE_IO_SUSPENDED:
				return -1;

			case RESCODE_IO_PROTOCOL_SHUTDOWN:
				return -3;
			}
		}
	}
	else
	{//no action defined
		default_encode_block:
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): INVOKING _DEFAULT_ ENCODE BLOCK (NONE): on raw_msg_size: '%ld' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->raw_msg_size);

		return sm_ptr->raw_msg_size;
	}

	return 0;

}

/**
 * 	@brief: sends text through socket. A simple frontend function.
 */
int
SendTextMessage (Session *sesn_ptr, const char *msg, size_t msglen)
{
	TransmissionMessage tmsg;
	tmsg.type=TRANSMSG_TEXT;
	tmsg.len=msglen;
	tmsg.msg=(void *)strndup(msg, msglen);
	tmsg.msg_packed=(void *)tmsg.msg;

	return SendToSocket (sesn_ptr, &tmsg, SOCKMSG_DONTWSFRAME);
}

/**
 * This is the entry point into the i/o system. TransmissionMessage payload is referenced (ie no copy) across to Session's SocketMessage output
 * buffer structure, which is a two stage process: 1) copied into raw 2)if extra processing is required (e.g SocketMessage envelop)
 * that get copied into processed. For regular text, raw is referenced direct into processed.
 * Stage 2 happen in the next function. This function adapts TransmissionMessage into Session->Socket->SocketMessageOut->Raw
 * Phase 2 is Session->Socket->SocketMessageOut->Processed
 *
 * All objects managed memory from here on
 *
 * @dynamic_memory SocketMessage: when pre-existing queue could not be flushed, msg will be enqueued. SocketMessage struct
 * is not affected. TransmissionMessage referenced across in MessageQueue .
 *
 * @returns 0: message queued
 * @returns -2: logical or processing error
 */
ssize_t
SendToSocket (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned flag)
{

	//we must flush out queue first to preserve sequence of message generation
	if ((DispatchSocketMessageQueue (sesn_ptr, 0))<0)
	{
		//dequeueing failed. save current message to the queue
		SocketMessage *sm_ptr_aux=calloc(1, sizeof(SocketMessage));
		if (sm_ptr_aux)
		{
			if (tmsg_ptr->type==TRANSMSG_PROTOBUF)
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING PROTOBUF TO OUT MessageQueue: RAW SocketMessage: size: '%lu'", __func__,
						pthread_self(), SESSION_ID(sesn_ptr), tmsg_ptr->len);

				sm_ptr_aux->raw_msg_size=tmsg_ptr->len;
				sm_ptr_aux->_raw_msg=tmsg_ptr->msg_packed;//should not free in the calling environment
			}
			else
			if (tmsg_ptr->type==TRANSMSG_TEXT)//msg)//msg:cpy 1 must be freed in calling function
			{
				//save msg into SocketMessage
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING TEXT TO OUT MessageQueue: RAW SocketMessage: size: '%lu'", __func__,
					pthread_self(), SESSION_ID(sesn_ptr), tmsg_ptr->len);

				sm_ptr_aux->raw_msg_size=tmsg_ptr->len;//strlen ((char *)tmsg_ptr->msg);
				sm_ptr_aux->_raw_msg=tmsg_ptr->msg_packed;//mystrdup((char *)tmsg_ptr->msg);//msg:cpy 2
			}
			else
			if (tmsg_ptr->type==TRANSMSG_SOCKMSG)
			{
				SocketMessage *sm_ptr;
				sm_ptr=(SocketMessage *)tmsg_ptr->msg;

				if (sm_ptr->flag&SOCKMSG_ENCODED && sm_ptr->flag&SOCKMSG_WSFRAMED)
				{

					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING SOCKMSG TO OUT MessageQueue: FULLY ENCODED SocketMessage: size: '%ld'",
						__func__,pthread_self(), sesn_ptr->session_id, sm_ptr->processed_msg_size);

					sm_ptr_aux->written_msg_size=sm_ptr->written_msg_size;
					sm_ptr_aux->processed_msg_size=sm_ptr->processed_msg_size;//-written;///-written added
					sm_ptr_aux->_processed_msg=sm_ptr->_processed_msg;
					sm_ptr->processed_msg_size=0;//dont free in the calling function
					sm_ptr_aux->flag=sm_ptr->flag;
				}
				else
				if (sm_ptr->flag&SOCKMSG_DONTWSFRAME)
				{
					//extract text
					sm_ptr_aux->processed_msg_size=sm_ptr->processed_msg_size;//-written;///-written added
					sm_ptr_aux->_processed_msg=sm_ptr->_processed_msg;
				}
				else
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NOT ADDTING TO OUT MessageQueue: MSG FLAG UNRECOGNISED: size: '%ld'",
						__func__,pthread_self(), sesn_ptr->session_id, sm_ptr->processed_msg_size);
				}
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT FLUSH OUT MESSAGEQUEUE: ERROR ADDING TO QUEUE: WRONG PARAMS.",
					__func__,pthread_self(), sesn_ptr->session_id);

				free (sm_ptr_aux);

				return -2;//0; logical error
			}

			AddToQueue(&(sesn_ptr->message_queue_out.queue), sm_ptr_aux);

			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT FLUSH OUT MESSAGEQUEUE: QUEUEING ESSAGE: msg size='%ld'. Queue size (nEntries='%lu')",
				__func__,pthread_self(), sesn_ptr->session_id, sm_ptr_aux->processed_msg_size, sesn_ptr->message_queue_out.queue.nEntries);
		}//if sm_ptr_aux

		return 0;//queued or partial write
	}

	//Adapt TransmissionMessage format for final SocketMessage type
	if (tmsg_ptr->type==TRANSMSG_PROTOBUF)
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING PROTOBUF TO OUT MessageQueue: RAW SocketMessage: size: '%lu'", __func__,
				pthread_self(), SESSION_ID(sesn_ptr), tmsg_ptr->len);
#endif
		sesn_ptr->ssptr->socket_msg_out.raw_msg_size=tmsg_ptr->len;
		sesn_ptr->ssptr->socket_msg_out._raw_msg=tmsg_ptr->msg_packed;
	}
	else //reference payload into raw output buffer
	if (tmsg_ptr->type==TRANSMSG_TEXT)//msg)//msg:cpy 1 must be freed in calling function
	{
		//save msg into SocketMessage
		//outputting the string can cause valgrind warning, because these are not guaratneed to be null terminated strings
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING TEXT TO OUT MessageQueue: RAW SocketMessage: msg: '...' size: '%lu'", __func__,
			pthread_self(), SESSION_ID(sesn_ptr), /*tmsg_ptr->msg_packed,*/ tmsg_ptr->len);
#endif
		sesn_ptr->ssptr->socket_msg_out.raw_msg_size=tmsg_ptr->len;
		sesn_ptr->ssptr->socket_msg_out._raw_msg=tmsg_ptr->msg_packed;//mystrdup((char *)tmsg_ptr->msg);//copy 2
	}
	else
	if (tmsg_ptr->type==TRANSMSG_SOCKMSG)
	{
		SocketMessage *sm_ptr;
		sm_ptr=(SocketMessage *)tmsg_ptr->msg;

		if (sm_ptr->flag&SOCKMSG_ENCODED && sm_ptr->flag&SOCKMSG_WSFRAMED)
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ADDTING SOCKMSG TO OUT MessageQueue: PREVIOUSLY FULLY ENCODED SocketMessage: size: '%ld'",
				__func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->processed_msg_size);
#endif
			//relay buffer out
			sesn_ptr->ssptr->socket_msg_out._raw_msg=sm_ptr->_processed_msg;//ref:2
			sesn_ptr->ssptr->socket_msg_out.raw_msg_size=sm_ptr->processed_msg_size;
			sesn_ptr->ssptr->socket_msg_out.flag=sm_ptr->flag;

			sm_ptr->processed_msg_size=0;//Effectively reduce ref count so we dont inadvertently free in the original carrier struct
		}
		else//TODO: consolidate with above
		if (sm_ptr->flag&SOCKMSG_DONTWSFRAME)
		{
			//extract text
			sesn_ptr->ssptr->socket_msg_out.raw_msg_size=sm_ptr->processed_msg_size;//-written;///-written added
			sesn_ptr->ssptr->socket_msg_out._raw_msg=sm_ptr->_processed_msg;
			sesn_ptr->ssptr->socket_msg_out.flag=sm_ptr->flag;

			//Effectively reduce ref count so we dont inadvertently free in the original carrier struct
			sm_ptr->processed_msg_size=0;
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): UNABLE TO PROCESS PREPACKED SOCKET MESSAGE: MSG FLAG UNRECOGNISED: size: '%ld'",
				__func__, pthread_self(), SESSION_ID(sesn_ptr), sm_ptr->processed_msg_size);

			return -2;
		}
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT DETERMINE TRANSMISSION MSG TYPE: '%d'.",
			__func__, pthread_self(), SESSION_ID(sesn_ptr), tmsg_ptr->type);

		//SocketMessage memory not affected
		return -2;//0;
	}

	//all buffer memory is transfered by reference to out.raw no clean up is done here
	//MesssageTransission object is to be managed by calling environment
	//TODO: not necessary to reference a SocketMessage *: &(sesn_ptr->ssptr->socket_msg_out); it is already been shifted
	return _SendToSocket(sesn_ptr, &(sesn_ptr->ssptr->socket_msg_out), NULL, flag);

}

//
//should only be used with fully connected Session as it implements the  WebSocket protocol
//out.raw buffer is already loaded with input data ready to be processed.
//it first processes raw  then shift that into processed buffer depending on flags
//On error it cleans up all memory stashed in out.raw buffer.
//@param sock_msg_ptr SocketMessage containing message information, most likely from previous incoming buffer. If this available it is used
//@param msg null terminated string
//@param flag SOCKMSG_DONTENCODE isntructs to send the buffer in it raw format
//SOCKMG_DONTWSFRME instructs to send without WebSocket framing

// return values must be consistent with whatever _dispatchosocket returns.
//	@return 0: partial write, buffer queued
//	@returns -1: i/o error from dispatch, suspend session
//	@returns -2: logical or processing error
//	@returns -3: websocket encoding error: sock_msg_ptr cleaned out

//
inline static ssize_t
_SendToSocket (Session *sesn_ptr, SocketMessage *sock_msg_ptr, const char *msg, unsigned flag)
{
	//>>>>> 2)SECOND: Process RAW buffer and shift to processed buffer

	//TODO: THIS if-else block SHOULD BE REFACTORED INTO _SocketMessageEncode()
	if ((flag&SOCKMSG_DONTWSFRAME) || ((sesn_ptr->ssptr->socket_msg_out.flag&SOCKMSG_ENCODED) && (sesn_ptr->ssptr->socket_msg_out.flag&SOCKMSG_ENCODED))) {
		//straight through; no processing applied
		sesn_ptr->ssptr->socket_msg_out.processed_msg_size = sesn_ptr->ssptr->socket_msg_out.raw_msg_size;
		sesn_ptr->ssptr->socket_msg_out._processed_msg = sesn_ptr->ssptr->socket_msg_out._raw_msg;//reuse buffer.
		sesn_ptr->ssptr->socket_msg_out.raw_msg_size = 0;//prevents raw_msg from being freed, because we are reusing the reference above
	} else {
		//allocate processed buffer
		sesn_ptr->ssptr->socket_msg_out.processed_msg_size = 2 * sesn_ptr->ssptr->socket_msg_out.raw_msg_size;
		sesn_ptr->ssptr->socket_msg_out._processed_msg = calloc(2, sesn_ptr->ssptr->socket_msg_out.raw_msg_size);

		int rc = 0;
		if ((rc = _SocketMessageEncode(sesn_ptr, SESSION_OUTSOCKMSG_TRANS_PTR(sesn_ptr), flag)) < 0) {
			DestructSocketMessage (&(sesn_ptr->ssptr->socket_msg_out));

			return rc;
		}
	}

	{//block
		//TODO: enable here and remove from hybie_encode
		//sesn_ptr->ssptr->socket_msg_out->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

		//this doesn't do buffer clean out--we do herein
		ssize_t ret_value = _DispatchSocketBuffer(sesn_ptr, &(sesn_ptr->ssptr->socket_msg_out));//this contains allocated raw + processed msgs

		if (ret_value > 0) {
			//success. otherwise this processed _msg will be queue'ed away
			DestructSocketMessage (&((sesn_ptr->ssptr->socket_msg_out)));
			sesn_ptr->ssptr->socket_msg_out.flag = 0;

			return ret_value;
		}

		if (ret_value == 0) {
			//partial or would-block. msg queued. wait until write out iteration
			DestructSocketMessage (&((sesn_ptr->ssptr->socket_msg_out)));
			sesn_ptr->ssptr->socket_msg_out.flag = 0;

			return ret_value;
		}

		if (ret_value == -1) {
			// i/o error
			DestructSocketMessage (&((sesn_ptr->ssptr->socket_msg_out)));
			SuspendSession (InstanceHolderFromClientContext(sesn_ptr), SOFT_SUSPENSE);
			//fall through below, which applies to all other <0 values
		}

		sesn_ptr->ssptr->socket_msg_out.flag = 0;

		return ret_value;

	}//end of block


}

//
//	@brief sends the Websocket framed messageto destination. Implements nonblocking sockets behavior. If blocked it will iterate one more time bfore writig the
//	the unsent stream to the socket queue.
//	writes out buf2 i.e. the ordinarily websocket processed.
//	this should only be used with fully established ServiceSession.
//	Don't call this direct. It must be called with SendTo
// 	@return amount of bytes retunr. 0 if blocked, -1 on i/o error.
//	@side-effect	 SocketMessage queued on partial write, indicating remaining amount
//	to be sent on future invocation
//
//	@dynamic_memory SocketMessage: when partial write. processed_buf referenced in new queue. Doesn't free.
//
//	@returns >0: amount of bytes written
//	@return 0: partial write, buffer queued. processed_buf referenced in new queue
//	@returns -1: i/o error from dispatch, suspend session
//	@returns -2: logical or processing error
//
inline static ssize_t
_DispatchSocketBuffer (Session *sesn_ptr, SocketMessage *sock_msg_ptr)

{
	ssize_t written, write_upto;
	ssize_t result;
	int loop_counter;
	SocketMessage *sm_ptr;
	bool blocking_io=false;

	if (sock_msg_ptr) sm_ptr=sock_msg_ptr;
	else sm_ptr=&(sesn_ptr->ssptr->socket_msg_out);//default to outgoing

	if (sm_ptr->written_msg_size>0) ///
	{
		written=sm_ptr->written_msg_size;//remember where we left off last
		//syslog(LOG_DEBUG, "DispatchSocketBufferWS (pid:'%lu' cid:'%lu'): QUEUE CONTAINS PARTIALLY WRITTEN MESSAGE: CURRENT POSITION: '%lu'. ORIGINAL msg size='%ld'. written='%ld' Queue size (nEntries='%lu')",
			//	sesn_ptr->pid, sesn_ptr->session_id, written, sm_ptr->processed_msg_size);
	}
	else written=0;

	loop_counter=0;

	write_upto=sm_ptr->processed_msg_size;
	int myerrno=0;

	while (written < write_upto)// || loop_counter<2)
	{
		//loop_counter++; //1,2
		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE))
		{
			ERR_clear_error();
			result=SSL_write(sesn_ptr->session_crypto.ssl, sm_ptr->_processed_msg+(written),(write_upto-written));
		}
		else
		{
			result=send(sesn_ptr->ssptr->sock, sm_ptr->_processed_msg+(written), (write_upto-written), 0/*flags*/);
		}

		if (result==-1)//error
		{
			if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SECURE))
			{
				//errors other than blocking related https://www.openssl.org/docs/manmaster/ssl/SSL_get_error.html
				int err=SSL_get_error(sesn_ptr->session_crypto.ssl, result);
				if (err==SSL_ERROR_WANT_WRITE || err==SSL_ERROR_WANT_READ)//open SSL can return either during write
				{
					blocking_io=true;
				}

				myerrno=err;
			}
			else
			{
				if (myerrno == EAGAIN || myerrno==EWOULDBLOCK)	blocking_io=true;

				myerrno=errno;
			}

			break; //get out immediately
			/*
			if ((errno==EAGAIN) || (errno==EWOULDBLOCK) || (errno==EINPROGRESS))//-1
			{
				continue;//attempt reading again until loop_counter limit is reached 2x)
			}
			else break; //on i/o error get it out immediately
			*/
		}

		written += result;
	}//while

	if (written==write_upto)
	{
		SESSION_INCREMENT_TR(sesn_ptr, written);

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', msg_sz:'%lu', written_sz:'%lu'): SUCCESS: Written out full buffer..", __func__,
			pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr->processed_msg_size, written);
#endif
		//sm_ptr->flag=0;
		return write_upto;//success
	}
	else
	if ((written<write_upto)&&(blocking_io))//((myerrno == EAGAIN || myerrno==EWOULDBLOCK || myerrno == EINPROGRESS)))// we have to rely on this check because of the loop ret_value==-1 is not error if the first iteration resturned some bytes
	{
		if ((written>=0))//we have written less than what we wanted
		{
			SESSION_INCREMENT_TR(sesn_ptr, written);

			SocketMessage *sm_ptr_aux=calloc(1, sizeof(SocketMessage));
			if (sm_ptr_aux)
			{
				sm_ptr_aux->written_msg_size=written;
				//reassign relevant buffer
				//TODO: should reduce size by amount written or above offset by sm_ptr_aux->written_msg_size
				sm_ptr_aux->processed_msg_size=sm_ptr->processed_msg_size;//-written;///-written added
				sm_ptr_aux->_processed_msg=sm_ptr->_processed_msg;
				sm_ptr_aux->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

				sm_ptr->processed_msg_size=0;//dont free in the calling function

				AddToQueue(&(sesn_ptr->message_queue_out.queue), sm_ptr_aux);

				syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): QUEUEING PARTIAL MESSAGE: msg size='%ld'. written='%ld' Queue size (nEntries='%lu')",
					__func__,pthread_self(), sesn_ptr->session_id, sm_ptr_aux->processed_msg_size, written, sesn_ptr->message_queue_out.queue.nEntries);

				return 0;//queued
			}
		}
		else
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): WON'T QUEUE PARTIAL MESSAGE ('0' written):  written='%ld' Queue size (nEntries='%lu')",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), written, sesn_ptr->message_queue_out.queue.nEntries);

		}
	}
	else
	{
		//other i/o issues
		if ((result==-1) && (blocking_io==false))//(!(myerrno==EAGAIN) || !(myerrno==EWOULDBLOCK) || !(myerrno==EINPROGRESS)))
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', socket_fd:'%d', error:'%s'): ERROR WRITING to remote end (write attempt: '%d'). Amount written: '%ld'",
				  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), strerror(errno), loop_counter, written);

			shutdown(sesn_ptr->ssptr->sock, SHUT_RDWR);//SHUT_WR);//disallow in both directions
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR);

			return -1;// broken connection: suspend and clean out buffers we dont queue
		}
		else
		{
		}
	}

	return -2;//logical error

}

//
//@brief it is very important to preserve the order of message as this a framed stream oriented connection.
// if the calling function cares about the order, it should not send its own buffer if this function return <0
//
int DispatchSocketMessageQueue (Session *sesn_ptr, size_t entries)
{
	if (unlikely(IS_EMPTY(sesn_ptr))) return 0;

	if (sesn_ptr->message_queue_out.queue.nEntries==0)
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): NOTICE: Outgoing SocketMessage Queue is empty: returning...", __func__,pthread_self(), sesn_ptr->session_id);
#endif
		return 0;//neutral
	}

	size_t counter;

	if ((entries==0)||(entries>sesn_ptr->message_queue_out.queue.nEntries)) counter=sesn_ptr->message_queue_out.queue.nEntries;
	else counter=entries;

	size_t loop_counter=1;
	while (loop_counter++<=counter)
	{
		//to preserve the order of message, we only remove if send is successful
		SocketMessage *sm_ptr=RemoveFromQueue(&(sesn_ptr->message_queue_out.queue), 1);//don't remove the front
		if (sm_ptr)
		{
			size_t before_msg_size=sm_ptr->processed_msg_size-sm_ptr->written_msg_size;//remeber current size

			size_t after_msg_size=_SendToSocket (sesn_ptr, sm_ptr, NULL, 0);
			if (after_msg_size==before_msg_size)
			{
				syslog(LOG_DEBUG, "%s: (pid:'%lu' o:'%p' cid:'%lu'): BEFORE MSG_SIZE='%lu'. AFTER MSG_SIZE='%lu'",
						__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), before_msg_size, after_msg_size);

				sm_ptr=RemoveFromQueue(&(sesn_ptr->message_queue_out.queue), SOCKMSG_DONTWSFRAME);
				free(sm_ptr);
			}
			else
			{
				syslog(LOG_DEBUG, "%s: (pid:'%lu' o:'%p' cid:'%lu'): NOTICE: BEFORE MSG_SIZE='%lu'. AFTER MSG_SIZE='%lu': MESSAGE NOT REMOVED FROM QUEUE",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), before_msg_size, after_msg_size);
				return after_msg_size;
			}
		}
	}

	return 1;

}

/**
 * 	@brief: Given a Session's incoming SocketMessage queue (sesn_ptr->message_queue_in), join queue entries into a single SocketMessage.
 * 	Essentially results in one (huge) consolidated buffer.
 *
 * 	Depending on call_flags, the consolidated SocketMessage can be the Session's actual transient incoming SocketMessage (sesn_ptr->ssptr->socket_msg)
 * 	or, re-attached into the incoming SocketMessage queue, or returned as a free standing SocketMessage pointer. See flags below.
 *
 * 	@call_flag SOCKMSG_CONSOLIDATE_INSESSION: Consolidate into transient incoming socket message
 * 	@call_flag SOCKMSG_CONSOLIDATE_INSESSIONQUEUE: consolidate into incoming socket message queue
 * 	@call_flag SOCKMSG_LOCK_SOCKMSGQUEUE: lock Session's incoming SocketMessage queue
 * 	@returns:
 *  @locked sesn_ptr: must be locked din the calling environment
 *  @locked message_queue_in: should be locked din the calling environment unless SOCKMSG_LOCK_SOCKMSGQUEUE is passed
 *  @locks message_queue_in: if SOCKMSG_LOCK_SOCKMSGQUEUE is passed
 *  @unlocks message_queue_in:  if SOCKMSG_LOCK_SOCKMSGQUEUE is passed
 *  @dynamic_memory: creates new SocketMessage structure and ListEntry in Queue if SOCKMSG_CONSOLIDATE_INSESSIONQUEUE is  set, which the user must free
 *  @dynamic memory: if neither SOCKMSG_CONSOLIDATE_INSESSIONQUEUE or SOCKMSG_CONSOLIDATE_INSESSION is set returns a free standing structure
 *  				which the user must free
 */
UFSRVResult *ConsolidateSocketMessageQueue (Session *sesn_ptr, unsigned call_flags, UFSRVResult *res_ptr)
{
	unsigned char *consolidated_buffer;
	SocketMessage *sm_ptr_consolidated;
	int sm_errno = 0;

	//quick check before we launch into expensive locking
	___atomic_check:
	if (__sync_add_and_fetch (&sesn_ptr->message_queue_in.queue.nEntries, 0) == 0) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_NOTICE, "%s (pid='%lu' cid='%lu'): SOCKETMESSAGE QUEUE EMPTY: RETURNING...", __func__, pthread_self(), SESSION_ID(sesn_ptr));
#endif
		//technically not error, but we leave that up to the processing environment to work out context
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_EMPTY_RESOURCE)
	}

	if (call_flags&SOCKMSG_LOCK_SOCKMSGQUEUE) {
		if (!(MessageQueueLock(sesn_ptr, SESSION_INSOCKMSG_PTR(sesn_ptr), 0)==0)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}
	}

	if (call_flags&SOCKMSG_CONSOLIDATE_INSESSION) {
		sm_ptr_consolidated = &(sesn_ptr->ssptr->socket_msg);
	} else {
		sm_ptr_consolidated = calloc(1, sizeof(SocketMessage));
	}

	syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATED_PRE, __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr->message_queue_in.queue.nEntries, sm_ptr_consolidated->raw_msg_size, SESSION_CUMMULATIVE_RC(sesn_ptr), LOGCODE_IO_BUF_CONSOLIDATED_PRE);

	//prime the buffer by factor of one if it's empty so realloc can work.
	if (sm_ptr_consolidated->raw_msg_size == 0) sm_ptr_consolidated->_raw_msg = calloc(1, sizeof(unsigned char));

	QueueEntry *qe_ptr = NULL;
	SocketMessage *sm_ptr_aux;
	int blocksz_factor = 1;

	while (sesn_ptr->message_queue_in.queue.nEntries != 0) {
		qe_ptr = deQueue(&(sesn_ptr->message_queue_in.queue));

		if ((sm_ptr_aux = (SocketMessage *)qe_ptr->whatever)) {
			//at some prior i/o cycle we hit an error
			if (!(sm_ptr_aux->sm_errno == 0)) {
				sm_errno = sm_ptr_aux->sm_errno;
        DestructSocketMessage(sm_ptr_aux);
				free (sm_ptr_aux);
				free(qe_ptr);

				continue;
			}

#ifdef __UF_FULLDEBUG
			syslog(LOG_INFO, "%s (pid:%lu cid='%lu'): DEQUEUEING (msg count='%lu')... ", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr->message_queue_in.queue.nEntries+1);//+1 because dequeue above decrements
#endif
			unsigned char *tmp_hb = NULL;
			if (!(tmp_hb = realloc(sm_ptr_consolidated->_raw_msg, sm_ptr_consolidated->raw_msg_size+sm_ptr_aux->raw_msg_size))) {
				error_recovery:
				//memory allocation error: clean up brute force.. this is mostly fatal condition
				syslog(LOG_INFO, "%s (pid:%lu cid='%lu'): MEMORY ERROR: COULD NOT ALLOCATE MEMORY FOR BUFFER RESIZING... (msg count='%lu')... ", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr->message_queue_in.queue.nEntries+1);//+1 because dequeue above decrements
				//get rid of current element
				DestructSocketMessage(sm_ptr_aux);

				free (sm_ptr_aux);
				free(qe_ptr);

				// we only allocate this if we are not reusing transient incoming buffer
				if (!(call_flags&SOCKMSG_CONSOLIDATE_INSESSION))	free (sm_ptr_consolidated);
				//TODO: destroy queue

				if (call_flags&SOCKMSG_LOCK_SOCKMSGQUEUE) {
					MessageQueueUnLock(sesn_ptr, SESSION_INSOCKMSG_PTR(sesn_ptr));
				}

				_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MEMORY_EXHAUSTED)
			}

			//repoint to new expanded buffer
			sm_ptr_consolidated->_raw_msg = tmp_hb;

			//stash into the new allocated space, beginning at current offset
			memcpy (sm_ptr_consolidated->_raw_msg + sm_ptr_consolidated->raw_msg_size, sm_ptr_aux->_raw_msg, sm_ptr_aux->raw_msg_size);

			//update offset
			sm_ptr_consolidated->raw_msg_size += sm_ptr_aux->raw_msg_size;

			//update total bytes read, as threads reading into queue cannot do that
			SESSION_INCREMENT_TR(sesn_ptr, sm_ptr_aux->raw_msg_size);

			//update dynamic block sizing, again on behalf previously restricted threads
			if (sm_ptr_aux->raw_msg_size <= SESSION_SOCKETBLOCKSZ(sesn_ptr)) {
				//only do it if we have not reached global max limit on blocksz
				if (SESSION_SOCKETBLOCKSZ(sesn_ptr) < _CONF_READ_MAXBLOCKSZ(masterptr))	blocksz_factor++;
				else {
					blocksz_factor--;
					if (blocksz_factor < 0)	blocksz_factor = 1;
				}
			}

#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATED, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr_consolidated->raw_msg_size, LOGCODE_IO_BUF_CONSOLIDATED);
#endif

			DestructSocketMessage(sm_ptr_aux);
			free (sm_ptr_aux);
		}

		free(qe_ptr);
	}

	//restore error value recovered from consolidation if any. We only restore the last recorded value
	sm_ptr_consolidated->sm_errno = sm_errno;

	if ((blocksz_factor > 0) && (sm_ptr_consolidated->sm_errno == 0)) {
		unsigned new_blocksz = (unsigned) pow (SESSION_SOCKETBLOCKSZ(sesn_ptr), blocksz_factor);

		if (new_blocksz > _CONF_READ_MAXBLOCKSZ(masterptr))	new_blocksz = _CONF_READ_MAXBLOCKSZ(masterptr);

		SESSION_SOCKETBLOCKSZ(sesn_ptr) = new_blocksz;

		//good chance buffer is not drained, so lets cycle again
		SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLEREQUEST);
	}

	syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATED_FIN,
			__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sm_ptr_consolidated->raw_msg_size, SESSION_CUMMULATIVE_RC(sesn_ptr), SESSION_SOCKETBLOCKSZ(sesn_ptr), sm_errno, LOGCODE_IO_BUF_CONSOLIDATED_FIN);

	//put this back into the now empty queue
	if (call_flags&SOCKMSG_CONSOLIDATE_INSESSIONQUEUE) {
		AddToQueue(SESSION_INSOCKMSG_QUEUE_PTR(sesn_ptr), sm_ptr_consolidated);
	}

	if (call_flags&SOCKMSG_LOCK_SOCKMSGQUEUE) {
		MessageQueueUnLock(sesn_ptr, SESSION_INSOCKMSG_PTR(sesn_ptr));
	}

	_RETURN_RESULT_RES(res_ptr, sm_ptr_consolidated, RESULT_TYPE_SUCCESS, RESCODE_LOGIC_WITH_RESOURCE)

}

/**
 *	@brief: invokes standard error propagation process. Doesn't touch the deallocation of buffers
 *
 *	param call_flags: SOCKMSG_LOCK_SOCKMSGQUEUE. This is passed off by other callers
 *	param call_flags: SOCKMSG_CONSOLIDATE_INSESSION: consolidate queue into transitional buffer
 * 	@locked sesn_ptr: must be locked in calling environment
 */
void ErrorFromSocket (InstanceHolderForSession *instance_sesn_ptr, unsigned call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR);
	RemoveSessionToMonitoredWorkEvents(instance_sesn_ptr);

	//consolidate queue into transitional incoming buffer
	if (call_flags&SOCKMSG_CONSOLIDATE_INSESSION) {
		UFSRVResult res;
		ConsolidateSocketMessageQueue(sesn_ptr, call_flags, &res);
		if (res.result_type == RESULT_TYPE_SUCCESS) {

		} else if (res.result_code != RESCODE_LOGIC_EMPTY_RESOURCE) {//ie queue was not empty
			//error
		}
	}

	//invoke decode lifecycle, which shifts data to processed. Nocommand processing involved here
	_SocketMessageDecode(sesn_ptr, SESSION_INSOCKMSG_TRANS_PTR(sesn_ptr), call_flags);

	if (_PROTOCOL_CLLBACKS_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_ERROR_INVOKE(	protocols_registry_ptr,
																PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
																sesn_ptr, call_flags);
	}

	SuspendSession (instance_sesn_ptr, SOFT_SUSPENSE);

}
