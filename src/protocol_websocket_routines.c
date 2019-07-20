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
#include <main.h>
#include <utils.h>
#include <list.h>
#include <session.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/md5.h> /* md5 hash */
#include <openssl/sha.h> /* sha1 hash */
#include <protocol_websocket.h>
#include <protocol_websocket_routines.h>
#include <websocket_parser_type.h>

typedef enum {
	/**
	 * @brief Support to model unknown op code.
	 */
	UNKNOWN_OP_CODE = -1,
	/**
	 * @brief Denotes a continuation frame.
	 */
	CONTINUATION_FRAME = 0,
	/**
	 * @brief Denotes a text frame (utf-8 content) and the first
	 * frame of the message.
	 */
	TEXT_FRAME         = 1,
	/**
	 * @brief Denotes a binary frame and the first frame of the
	 * message.
	 */
	BINARY_FRAME       = 2,
	/**
	 * @brief Denotes a close frame request.
	 */
	CLOSE_FRAME        = 8,
	/**
	 * @brief Denotes a ping frame (used to ring test the circuit
	 * and to keep alive the connection).
	 */
	PING_FRAME         = 9,
	/**
	 * @brief Denotes a pong frame (reply to ping request).
	 */
	PONG_FRAME         = 10
} WS_OpCodes;

inline static void
mask_content (unsigned char *payload, int payload_size, char *mask, int desp);

int
encode_hixie(u_char const *src, size_t srclength, char *target, size_t targsize)
{
    int sz = 0, len = 0;
    target[sz++] = '\x00';
    len = b64_ntop(src, srclength, target+sz, targsize-sz);
    if (len < 0) {
        return len;
    }
    sz += len;
    target[sz++] = '\xff';
    return sz;
}

int
decode_hixie(char *src, size_t srclength, u_char *target, size_t targsize, unsigned int *opcode, unsigned int *left, size_t *frame_count)

 {
    char *start, *end, cntstr[4];
    int i, len, framecount = 0, retlen = 0;
    unsigned char chr;
    if ((src[0] != '\x00') || (src[srclength-1] != '\xff')) {
        say("WebSocket framing error\n");
        return -1;
    }
    *left = srclength;

    if (srclength == 2 &&
        (src[0] == '\xff') && 
        (src[1] == '\x00')) {
        // client sent orderly close frame
        *opcode = 0x8; // Close frame
        return 0;
    }
    *opcode = 0x1; // Text frame

    start = src+1; // Skip '\x00' start
    do {
        /* We may have more than one frame */
        end = (char *)memchr(start, '\xff', srclength);
        *end = '\x00';
        len = b64_pton(start, target+retlen, targsize-retlen);
        if (len < 0) {
            return len;
        }
        retlen += len;
        start = end + 2; // Skip '\xff' end and '\x00' start 
        framecount++;
    } while (end < (src+srclength-1));
   
//AA
/*
 if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }
*/
    *frame_count=framecount;
    *left = 0;
    return retlen;
}
/*
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	  +-+-+-+-+-------+-+-------------+-------------------------------+
	  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	  |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
	  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
	  | |1|2|3|       |K|             |                               |
	  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	  |     Extended payload length continued, if payload len == 127  |
	  + - - - - - - - - - - - - - - - +-------------------------------+
	  |                               |Masking-key, if MASK set to 1  |
	  +-------------------------------+-------------------------------+
	  | Masking-key (continued)       |          Payload Data         |
	  +-------------------------------- - - - - - - - - - - - - - - - +
	  :                     Payload Data continued ...                :
	  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	  |                     Payload Data continued ...                |
	  +---------------------------------------------------------------+
	private static final int OP_CONTINUATION =  0;
    private static final int OP_TEXT         =  1;
    private static final int OP_BINARY       =  2;
    private static final int OP_CLOSE        =  8;
    private static final int OP_PING         =  9;
    private static final int OP_PONG         = 10;
*/

int
encode_hybi(SocketMessage *sm_ptr, const unsigned char *src, size_t srclength, unsigned char *target, size_t targsize, unsigned int opcode)

{
	extern void set_16bit (int value, unsigned char * buffer);

    unsigned long long b64_sz, len_offset = 1, payload_offset = 2;//, len = 0;
    
    if ((int)srclength <= 0)
    {
        return 0;
    }

    memset(target, 0, targsize);

    b64_sz = ((srclength - 1) / 3) * 4 + 4;

    target[0] = (char)((opcode & 0x0F) | 0x80);

    if (b64_sz <= 125)
    {
        //target[1] = (char) b64_sz;
        target[1]|= srclength;
        payload_offset = 2;
    }
    else
	if ((b64_sz > 125) && (b64_sz < MAXBUF))//64k
	{
        /*target[1] = (char) 126;
        *(u_short*)&(target[2]) = htons(b64_sz);*/
		target[1] |= 126;
				/* set length into the next bytes */
		set_16bit (srclength, target + 2);
        payload_offset = 4;
    }
	else
	if (b64_sz < 9223372036854775807)
	{
	    syslog (LOG_NOTICE, "Sending frames larger than 65535 bytes not supported");
	    //target[1] = (char) 127;
		//*(u_long*)&(target[2]) = htonl(b64_sz);
		//payload_offset = 10;
		/* not supported yet */
		return -1;
	}

#if 1
    //AA- disable Base24
    memcpy(target+payload_offset, src, srclength);

    syslog (LOG_NOTICE, ">>>> Sending WS Frame with  payload_frame_offset: '%lld' length: '%llu'",  payload_offset, srclength+payload_offset);

    //TODO: shift out of here
    sm_ptr->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

    return srclength+payload_offset;
    //
#endif

#if 0
    //AA+ Base
    int len_encoded=b64_ntop (src, srclength, target+payload_offset, targsize-payload_offset);
    
    if (len_encoded < 0) {
        return len_encoded;
    }

    sm_ptr->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

    return len_encoded + payload_offset;
    //
#endif
}

int
encode_hybi_client	(SocketMessage *sm_ptr, const unsigned char *src, size_t srclength, unsigned char *target, size_t targsize, unsigned int opcode)

{
	extern void set_16bit (int value, unsigned char * buffer);

    unsigned long long b64_sz, len_offset = 1, payload_offset = 2;//, len = 0;

    if ((int)srclength <= 0)
    {
        return 0;
    }

    memset(target, 0, targsize);

    b64_sz = ((srclength - 1) / 3) * 4 + 4;

    target[0] = (char)((opcode & 0x0F) | 0x80);

    if (b64_sz <= 125)
    {
        //target[1] = (char) b64_sz;
        target[1]|= srclength;
        payload_offset = 2;
    }
    else
	if ((b64_sz > 125) && (b64_sz < MAXBUF))//64k
	{
        /*target[1] = (char) 126;
        *(u_short*)&(target[2]) = htons(b64_sz);*/
		target[1] |= 126;
				/* set length into the next bytes */
		set_16bit (srclength, target + 2);
        payload_offset = 4;
    }
	else
	if (b64_sz < 9223372036854775807)
	{
	    syslog (LOG_NOTICE, "Sending frames larger than 65535 bytes not supported");
	    //target[1] = (char) 127;
		//*(u_long*)&(target[2]) = htonl(b64_sz);
		//payload_offset = 10;
		/* not supported yet */
		return -1;
	}

    unsigned int mask_value=0;
	char mask[4];
	{
		//masking block
		set_bit (target + 1, 7);//mask bit

		mask_value = (unsigned int) random ();
		memset (mask, 0, 4);
		set_32bit (mask_value, (unsigned char *)mask);//pack it

		set_32bit (mask_value, target + payload_offset);

		payload_offset += 4;

		//printf (">> encoded : '%s' len='%d' payload_offset='%d'\n", target+payload_offset, len, payload_offset);
		mask_content (target+payload_offset , srclength, mask, 0);
	}

	/* according to message length */
	if (srclength < 126)
	{
		target[1] |= srclength;
	}
	else
	if (srclength < 65535)
	{
		// set the next header length is at least 65535
		target[1] |= 126;
		// set length into the next bytes
		set_16bit (srclength, target + 2);
	}
	else
	{
		//not supported
	}


#if 1
    //AA- disable Base24
    memcpy(target+payload_offset, src, srclength);

    syslog (LOG_NOTICE, ">>>> Sending WS Frame with  payload_frame_offset: '%lld' length: '%llu'",  payload_offset, srclength+payload_offset);

    //TODO: shift out of here
    sm_ptr->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

    return srclength+payload_offset;
    //
#endif

#if 0
		{//debug
			char j2[1024];memset(j2, 0, 1024);
			memcpy (j2, target+payload_offset, len);
			//printf (">> xor : '%s'\n", j2);
			//test to recover mask/encoded buffer: should match src
			int i;
			for (i = 0; i < len; i++)
			{
				j2[i] ^= mask[i%4];
			}

			char j3[1024];memset(j3, 0, 1024);
			int len2 = b64_pton((const char*)j2, j3, targsize);

			printf (">> reencoded : '%s' len='%d'\n", j3, len2);//, payload_offset);*/
		}
#endif
#if 0
    //AA+ Base
    int len_encoded=b64_ntop (src, srclength, target+payload_offset, targsize-payload_offset);

    if (len_encoded < 0) {
        return len_encoded;
    }

    sm_ptr->flag|=(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

    return len_encoded + payload_offset;
    //
#endif

}

int
decode_hybi (SocketMessage *sm_ptr, unsigned char *src, ssize_t srclength, unsigned char *target, ssize_t targsize, unsigned int *opcode, unsigned int *left)
{
  unsigned char *frame, *mask, *payload, save_char, cntstr[4];
  int masked = 0;
  int i = 0, len = 0, framecount = 0;
  ssize_t remaining;
  unsigned int target_offset = 0, hdr_length = 0, payload_length = 0;

  *left = srclength;
  frame = src;

#ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "%s {pid:'%lu'}: Deocde new frame length '%lu'...", __func__, pthread_self(), srclength);
#endif

	while (1) {
		// Need at least two bytes of the header
		// Find beginning of next frame. First time hdr_length, masked and
		// payload_length are zero
		frame += hdr_length + 4*masked + payload_length;

		if (frame > src + srclength) {
			//fragmentation: payload size indicates more data are to be read from socket
			sm_ptr->missing_msg_size = frame - (src + srclength);
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Received a partial frame from client: need '%ld' more bytes from next frame", __func__, pthread_self(), sm_ptr->missing_msg_size);

			break;
		}

		remaining = (src + srclength) - frame;

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Remaining: '%ld'",  __func__, remaining);
#endif

		if (remaining < 2) {
			//this should be zero if we processed and every thing adds up. by the end 'frame' should point to the end of the str so net is 0
			if (remaining !=0)	syslog(LOG_NOTICE, "%s {pid:'%lu'}: Truncated frame header from client", __func__, pthread_self());
			break;
		}

		framecount++;

		*opcode = frame[0] & 0x0f;//00001111
		masked = (frame[1] & 0x80) >> 7; //10000000 shift the value of the most sgnificnt to the right, padding with zero

		if (*opcode == 0x8) {
			syslog(LOG_DEBUG, "%s {p:'%lu'}: client sent orderly close frame...", __func__, pthread_self());

			break;
		} else if (*opcode == PING_FRAME) {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: RECEIVED PING...", __func__, pthread_self());
		} else if (*opcode == PONG_FRAME) {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: RECEIVED PONG...", __func__, pthread_self());
		}

		payload_length = frame[1] & 0x7f;
		if (payload_length < 126) {
			hdr_length = 2;
			//frame += 2 * sizeof(char);
		} else if (payload_length == 126) {
			payload_length = (frame[2] << 8) + frame[3];
			hdr_length = 4;
		} else if (payload_length == 127) {
			//get next 8 bytes
			payload_length = 0;
			payload_length |= ((long)(frame[0]) << 56);
			payload_length |= ((long)(frame[1]) << 48);
			payload_length |= ((long)(frame[2]) << 40);
			payload_length |= ((long)(frame[3]) << 32);
			payload_length |= ((long)(frame[4]) << 24);
			payload_length |= ((long)(frame[5]) << 16);
			payload_length |= ((long)(frame[6]) << 8);
			payload_length |= frame[7];

			hdr_length = 10;

			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Receiving frames larger than 65535 bytes(actual: '%d' bytes)  not supported: returning", __func__, pthread_self(), payload_length);

			return -1;
		} else {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: RECEIVED UNSUPPORTED payload length: '%u'", __func__, pthread_self(), payload_length);

			return -1;

		}

		if ((hdr_length + 4*masked + payload_length) > remaining) {
			sm_ptr->holding_buffer_msg_size	=	remaining;//we hold that many in frame fragment raw_unprocessed_msg_size=remaining;
			sm_ptr->raw_msg_cur_pos					=	frame - src;//remember begining of frame fragment in raw_buffer
			framecount--;

			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Current frame is fragmented: frame size: '%d'. Currently in raw_buffer: '%ld'. Current position in raw_buffer: '%ld'. Frame count decremented to: '%d'",
					__func__, pthread_self(), hdr_length + 4*masked + payload_length, sm_ptr->holding_buffer_msg_size, sm_ptr->raw_msg_cur_pos, framecount);

			continue;
		}

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: payload_length: '%u'. header_length: '%d'. raw remaining: %ld", __func__, pthread_self(),
				payload_length, hdr_length+4*masked, remaining-(payload_length+hdr_length+4*masked));
#endif

		payload = frame + hdr_length + 4*masked;

		if (*opcode != 1 && *opcode != 2) {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Ignoring non-data frame, opcode 0x%x", __func__, pthread_self(), *opcode);

			continue;
		}

		if (payload_length == 0) {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Ignoring empty frame", __func__, pthread_self());
			continue;
		}

		if ((payload_length > 0) && (!masked)) {
			syslog(LOG_NOTICE, "%s {pid:'%lu'}: Received unmasked payload from client", __func__, pthread_self());

			//return -1; //AA should return
		}


#if 0 //Base64 block
		// Terminate with a null for base64 decode
		save_char = payload[payload_length];
		payload[payload_length] = '\0';

		// unmask the data. client always sends data masked as per protocol
		mask = payload - 4;
		for (i = 0; i < payload_length; i++)
		{
			payload[i] ^= mask[i%4];
		}

		// base64 decode the data
		len = b64_pton((const char*)payload, target+target_offset, targsize);
		//len=payload_length;/// //AA+ remove when disabling Base64

		// Restore the first character of the next frame
		payload[payload_length] = save_char;

		///AA+ Base64
		if (len < 0)
		{
			syslog(LOG_NOTICE, "decode_hybi: Base64 decode error code %d", len);
			return len;
		}
		//

		*(target+target_offset+len)='\0';
		 syslog(LOG_DEBUG, "decode_hybi: Finished decoding: '%s'", (target+target_offset));

		target_offset += (len+1);//increment len to move past the '0'

		//syslog(LOG_INFO, "decode_hybi:  len %d, raw %s", len, frame);
#endif

		//Non Base64 block

		// point at the start of the 4-byte mask. client always sends data masked as per protocol
		mask = payload - 4;
		for (i = 0; i < payload_length; i++) {
			payload[i] ^= mask[i % 4];//apply first 4 bytes which represent the masking key set by the client
		}

		len = payload_length;/// //AA+ remove when disabling Base64

		//not needed with binary
		///*(target+target_offset+len)='\0';
		memcpy (target + target_offset, payload,  len);//move data into buffer

		 sm_ptr->frame_index[framecount-1] = len;//to be able to read off individual frame lengths instead of relying on \0 marker

		 syslog(LOG_DEBUG, "%s {pid:'%lu'}: Finished decoding: frame_count:'%d' payload_length: '%lu' data: '%s'", __func__, pthread_self(), framecount, sm_ptr->frame_index[framecount-1], target+target_offset);

		 target_offset += (len);//+1);//increment len to move past the '0' <-- not applicable for non-b64
	}
    
    *left								=	sm_ptr->missing_msg_size;//remaining;
    sm_ptr->frame_count	=	framecount;

#ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "%s {pid:'%lu'}: Finished decoding: final size: '%d'", __func__, target_offset);
#endif

    return target_offset;//zero indicates we have large frame for which we need to assemble more fragments before decoding

}

int
decode_hybi_client (SocketMessage *sm_ptr, unsigned char *src, ssize_t srclength, unsigned char *target, ssize_t targsize, unsigned int *opcode, unsigned int *left)

{
    unsigned char *frame, *mask, *payload, save_char, cntstr[4];;
    int masked = 0;
    int i = 0, len=0, framecount = 0;
    ssize_t remaining;
    unsigned int target_offset = 0, hdr_length = 0, payload_length = 0;

    *left = srclength;
    frame = src;

    syslog(LOG_DEBUG, "%s: Deocde new frame length '%lu'...", __func__, srclength);

	while (1)
	{
		// Need at least two bytes of the header
		// Find beginning of next frame. First time hdr_length, masked and
		// payload_length are zero
		frame += hdr_length + 4*masked + payload_length;

		if (frame > src + srclength)
		{
			//fragmentation: payload size indicates more data are to be read from socket
			sm_ptr->missing_msg_size=frame-(src + srclength);
			syslog(LOG_DEBUG, "%s: Received a partial frame from client: need '%ld' more bytes from next frame", __func__, sm_ptr->missing_msg_size);

			break;
		}

		remaining = (src + srclength) - frame;
		syslog(LOG_DEBUG, "%s: Remaining: '%ld'",  __func__, remaining);


		if (remaining < 2)
		{
			//this should be zero if we processed and every thing adds up. by the end 'frame' should point to the end of the str so net is 0
			if (remaining !=0)	syslog(LOG_NOTICE, "%s: Truncated frame header from client", __func__);
			break;
		}

		framecount++;

		*opcode = frame[0] & 0x0f;//00001111
		masked = (frame[1] & 0x80) >> 7; //10000000 shift the value of the most sgnificnt to the right, padding with zero

		if (*opcode == 0x8)
		{
			syslog(LOG_DEBUG, "%s: client sent orderly close frame...", __func__);

			break;
		}
		else
		if (*opcode==PING_FRAME)
		{
			syslog(LOG_DEBUG, "%s: >>> RECEIVED PING...", __func__);
		}
		else
		if (*opcode==PONG_FRAME)
		{
			syslog(LOG_DEBUG, "%s: >>> RECEIVED PONG...", __func__);
		}

		payload_length = frame[1] & 0x7f;
		if (payload_length < 126)
		{
			hdr_length = 2;
			//frame += 2 * sizeof(char);
		}
		else
		if (payload_length == 126)
		{
			payload_length = (frame[2] << 8) + frame[3];
			hdr_length = 4;
		}
		else
		if (payload_length==127)
		{
			//get next 8 bytes
			payload_length = 0;
			payload_length |= ((long)(frame[0]) << 56);
			payload_length |= ((long)(frame[1]) << 48);
			payload_length |= ((long)(frame[2]) << 40);
			payload_length |= ((long)(frame[3]) << 32);
			payload_length |= ((long)(frame[4]) << 24);
			payload_length |= ((long)(frame[5]) << 16);
			payload_length |= ((long)(frame[6]) << 8);
			payload_length |= frame[7];

			hdr_length = 10;

			syslog(LOG_DEBUG, "%s: Receiving frames larger than 65535 bytes(actual: '%d' bytes)  not supported: returning", __func__, payload_length);

			return -1;
		}
		else
		{
			syslog(LOG_DEBUG, "%s: ERROR: RECEIVED UNSUPPORTED payload length: '%u'", __func__, payload_length);

			return -1;

		}

		if ((hdr_length + 4*masked + payload_length) > remaining)
		{
			sm_ptr->holding_buffer_msg_size=remaining;//we hold that many in frame fragment raw_unprocessed_msg_size=remaining;
			sm_ptr->raw_msg_cur_pos=frame-src;//remember begining of frame fragment in raw_buffer
			framecount--;

			syslog(LOG_DEBUG, "%s: Current frame is fragmented: frame size: '%d'. Currently in raw_buffer: '%ld'. Current position in raw_buffer: '%ld'. Frame count decremented to: '%d'",
					__func__, hdr_length + 4*masked + payload_length, sm_ptr->holding_buffer_msg_size, sm_ptr->raw_msg_cur_pos, framecount);

			continue;
		}

		syslog(LOG_DEBUG, "%s: payload_length: '%u'. header_length: '%d'. raw remaining: %ld\n", __func__,
				payload_length, hdr_length+4*masked, remaining-(payload_length+hdr_length+4*masked));

		payload = frame + hdr_length + 4*masked;

		if (*opcode != 1 && *opcode != 2)
		{
			syslog(LOG_DEBUG, "%s: Ignoring non-data frame, opcode 0x%x", __func__, *opcode);

			continue;
		}

		if (payload_length == 0)
		{
			syslog(LOG_DEBUG, "%s: Ignoring empty frame", __func__);
			continue;
		}

		//not relevant for client
		/*if ((payload_length > 0) && (!masked))
		{
			syslog(LOG_NOTICE, "%s: Received unmasked payload from client", __func__);

			//return -1; //AA should return
		}*/


#if 1
		//Non Base64 block
//not relevant for client
/*
		//syslog(LOG_DEBUG, "%s: TARGET OFFSET: '%d'. BEFORE MASKING char data: '%c' '%c' '%c'",
			//				 __func__, target_offset, payload[0], payload[1], payload[2]);
			// point at the start of the 4-byte mask. client always sends data masked as per protocol
		mask = payload - 4;
		for (i = 0; i < payload_length; i++)
		{
			payload[i] ^= mask[i%4];//apply first 4 bytes which represent the maskingkey set by the client
		}
*/
		len=payload_length;/// //AA+ remove when disabling Base64

		memcpy (target+target_offset, payload,  len);//move data into buffer

		sm_ptr->frame_index[framecount-1] = len;//to be able to read off individual frame lengths instead of relying on \0 marker

		syslog(LOG_DEBUG, "%s: Finished decoding: frame_count:'%d' payload_length: '%lu' data: '%s'",
			 __func__, framecount, sm_ptr->frame_index[framecount-1], target+target_offset);

		target_offset += (len);//+1);//increment len to move past the '0' <-- not applicable for non-b64


		//syslog(LOG_INFO, "decode_hybi:  len %d, raw %s", len, frame);

#endif
	}//while

    *left=sm_ptr->missing_msg_size;//remaining;
    sm_ptr->frame_count=framecount;

    //unset flag
    //sm_ptr->flag&=~(SOCKMSG_ENCODED|SOCKMSG_WSFRAMED);

    syslog(LOG_DEBUG, "%s: Finished decoding: final size: '%d'", __func__, target_offset);

    return target_offset;//zero indicates we have large frame for which we need to assemble more fragments before decoding

}

#if 0
'GET / HTTP/1.1#015#012Host: 45.56.70.48#015#012Origin: http://45.56.70.48#015#012Sec-WebSocket-Version: 13#015#012Sec-WebSocket-Key: /gb3iAZigAftzdIh1SmqtQ==#015#012Connection: Upgrade#015#012Sec-WebSocket-Protocol: chat, superchat#015#012Cookie: session=yrdf|1427697571|cKxEDnNFWTnLTuQFoesX2y08cjmtjut2RRqQ8YoxkfB|81e24d2c77c329284a03bf948143be5409d3852712a60790c7772e405a69656f#015#012#015#012'
'GET / HTTP/1.1#015#012X-x-Agent: OWA#015#012Cookie: session=61414141410|1464781524|YIHmu9Ao6EPGHVugHVHitX#015#012X-UFSRVCID: 0#015#012X-CM-TOKEN: 0#015#012Upgrade: websocket#015#012Connection: Upgrade#015#012Sec-WebSocket-Key: cVA4L6lLENWjV6BtzTPKug==#015#012Sec-WebSocket-Version: 13#015#012Host: ufsrv.unfacd.com:19702#015#012Accept-Encoding: gzip#015#012User-Agent: okhttp/2.2.0#015#012X-Forwarded-For: 110.20.170.119#015#012#015#012'
#endif

int
parse_handshake(Session *sesn_ptr, char *handshake)
{
	extern int ws_parse(struct lws *wsi, unsigned char c);
	size_t handshake_len=strlen(handshake);

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: RECEIVED HANDSHAKE: '%s' len:'%lu'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), handshake, handshake_len);
#endif

	if ((handshake_len < 92) || (bcmp(handshake, "GET ", 4) != 0))
	{
		syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: FAILED HANDSHAKE LENGTH TEST (handshake:'%s')", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), handshake);

		return 0;
	}

	struct lws *wsi=calloc(1, sizeof(struct lws));
	wsi->u.hdr.ah=calloc(1, sizeof(struct allocated_headers));
	wsi->u.hdr.parser_state=WSI_TOKEN_NAME_PART;
	wsi->state=2;//WSI_STATE_HTTP_HEADERS;

	char *buf=handshake;


	while (handshake_len--) {
		if (ws_parse(wsi, *buf++)) {
			syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: WEBSOCKET HEADER PARSING FAILED: (handshake:'%s')", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), handshake);

			goto processing_error;
		}

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)	continue;
	}

	int idx=1;
	for ( ; idx<=wsi->u.hdr.ah->nfrag; idx++) {
		int j=wsi->u.hdr.ah->frags[idx].offset;
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG,"%s {pid:'%lu', o:'%p'}: %d)frag_offset:'%d'  len:'%d'  header_data: '%s' \n", idx, __func__, pthread_self(), sesn_ptr,
				wsi->u.hdr.ah->frags[idx].offset,
				wsi->u.hdr.ah->frags[idx].len,
				wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset);
#endif
	}

	ProtocolHeaderWebsocket *headers;
	Socket *sptr=NULL;

	sptr=sesn_ptr->ssptr;
	headers=&(sptr->protocol_header);
	headers->key1[0] = '\0';
	headers->key2[0] = '\0';
	headers->key3[0] = '\0';

	//get Cookie
	if ((idx=wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_COOKIE]) && (wsi->u.hdr.ah->frags[idx].len>0)) {
		size_t cookie_sz = wsi->u.hdr.ah->frags[idx].len;
		if (cookie_sz>CONFIG_MAX_COOKIE_SZ) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cookie_sz:'%lu'}: ERROR: REJECTING OVER SIZED COOKIE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cookie_sz);
			goto processing_error;
		}
		strncpy(sesn_ptr->session_cookie, wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset, cookie_sz+1);
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: COOKIE FOUND: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sesn_ptr->session_cookie);
#endif
	} else {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: HANDSHAKE NOTE: COOKIE NOT FOUND: REJECTING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		goto processing_error;
	}

	//get Xforwaded for
	if ((idx=wsi->u.hdr.ah->frag_index[X_FORWARDED_FOR])&& (wsi->u.hdr.ah->frags[idx].len>0)) {
		size_t haddress_sz = wsi->u.hdr.ah->frags[idx].len;
		if (haddress_sz>MAXHOSTLEN-1) {//MAXHOSTLEN includes null char
			syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu', address_sz:'%lu'}: HANDSHAKE ERROR: X-FOREARDED_FOR OVER SIZED: REJECTING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), haddress_sz);
			goto processing_error;
		}
		strncpy (sptr->haddress, wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset, haddress_sz+1);
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s: X-Forwarded-For FOUND: '%s'", __func__, sptr->haddress);
#endif
	} else {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: HANDSHAKE ERROR: X-Forwarded-For NOT FOUND: REJECTING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		goto processing_error;
	}

	//Sec-WebSocket-Key:
	if ((idx=wsi->u.hdr.ah->frag_index[WSI_TOKEN_KEY])&& (wsi->u.hdr.ah->frags[idx].len)) {
		strncpy (headers->key1, wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset, wsi->u.hdr.ah->frags[idx].len+1);
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: Sec-WebSocket-Key FOUND: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), headers->key1);
#endif
	} else {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: HANDSHAKE ERROR: Sec-WebSocket-Key NOT FOUND: REJECTING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		goto processing_error;
	}

	processing_success:
	free (wsi->u.hdr.ah);
	free (wsi);
	return 1;

	processing_error:
	free (wsi->u.hdr.ah);
	free (wsi);

	return 0;
}

int
parse_hixie76_key (char * key)
{
    unsigned long i, spaces = 0, num = 0;

    for (i=0; i < strlen(key); i++)
    {
        if (key[i] == ' ')
        {
            spaces += 1;
        }
        if ((key[i] >= 48) && (key[i] <= 57))
        {
            num = num * 10 + (key[i] - 48);
        }
    }

    return num / spaces;

}

int
gen_md5 (Socket *sptr, char *target)
{
	ProtocolHeaderWebsocket *headers;

    headers=&(sptr->protocol_header);
    unsigned long key1 = parse_hixie76_key(headers->key1);
    unsigned long key2 = parse_hixie76_key(headers->key2);
    char *key3 = headers->key3;

    MD5_CTX c;
    char in[HIXIE_MD5_DIGEST_LENGTH] = {
        key1 >> 24, key1 >> 16, key1 >> 8, key1,
        key2 >> 24, key2 >> 16, key2 >> 8, key2,
        key3[0], key3[1], key3[2], key3[3],
        key3[4], key3[5], key3[6], key3[7]
    };

    MD5_Init(&c);
    MD5_Update(&c, (void *)in, sizeof in);
    MD5_Final((void *)target, &c);

    target[HIXIE_MD5_DIGEST_LENGTH] = '\0';

    return 1;

}

//todo: for sha1 consider https://github.com/jdg/oauthconsumer/tree/master/Crypto
void
gen_sha1(Socket *sptr, char *target)
{
  SHA_CTX c;
  unsigned char hash[SHA_DIGEST_LENGTH];
  //int r;

  ProtocolHeaderWebsocket *headers;

	headers=&(sptr->protocol_header);

  SHA1_Init(&c);
  SHA1_Update(&c, headers->key1, strlen(headers->key1));
  SHA1_Update(&c, HYBI_GUID, 36);
  SHA1_Final(hash, &c);

  /*r = */b64_ntop(hash, sizeof hash, target, HYBI10_ACCEPTHDRLEN);

}

inline static void
mask_content (unsigned char *payload, int payload_size, char *mask, int desp)
{
	int iter       = 0;
	int mask_index = 0;
	int i;

	for (i = 0; i < payload_size ; i++)
	{
		payload[i] = (payload[i] ^ mask[i % 4]);
	}

	/*while (iter < payload_size)
	{
		// rotate mask and apply it
		mask_index = (iter + desp) % 4;
		payload[iter] ^= mask[mask_index];
		iter++;
	}*/ /* end while */

	return;
}
