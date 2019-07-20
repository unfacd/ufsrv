/*

    Copyright (C) 1999-2001  Ayman Akt
    Original Author: Ayman Akt (ayman@pobox.com)

 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrvresult_type.h>
#include <sockets.h>
#include <utils.h>
#include <nportredird.h>
#include <protocol.h>
#include <protocol_io.h>
#include <protocol_websocket_io.h>
#include <instrumentation_backend.h>
#include <http_session_type.h>
#include <mime.h>
#include <protocol_http_io.h>
#include <http_request_handler.h>


extern ufsrv *const masterptr;
extern  const  Protocol *const protocols_registry_ptr;

int
HttpSendMessage (Session *sesn_ptr, const char *msg, size_t msglen)
{
	TransmissionMessage tmsg;
	tmsg.type=TRANSMSG_TEXT;
	tmsg.len=msglen;
	tmsg.msg=strndup(msg, msglen);
	tmsg.msg_packed=(void *)tmsg.msg;

	return SendToSocket (sesn_ptr, &tmsg, SOCKMSG_DONTWSFRAME);
}


#include <sys/sendfile.h>

/**
 * 	@ALERT: You may need to check attch_ptr for NULL value as under special TESTING mode it is allowed to be that
 */
onion_connection_status HttpSendFile_orig (Session *sesn_ptr, const char *filename, AttachmentDescriptor *attch_ptr)
{
#if 0
	bool use_sendfile=true;

	if (unlikely(IS_EMPTY(filename)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Filename");
		return OCS_NOT_PROCESSED;
	}

	int fd=open(filename,O_RDONLY|O_CLOEXEC);

	if (fd<0)
	{
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: ERROR: COULD NOT OPEN OPEN FILE...", __func__, pthread_self(), sesn_ptr, filename);
		return OCS_NOT_PROCESSED;
	}

	if(O_CLOEXEC == 0)
	{ // Good compiler know how to cut this out
		int flags=fcntl(fd, F_GETFD);

		if (flags==-1)
		{
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: NOTICE: Could not Rrtrieving flags from file descriptor", __func__, pthread_self(), sesn_ptr, filename);
		}

		flags|=FD_CLOEXEC;
		if (fcntl(fd, F_SETFD, flags)==-1)
		{
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: NOTICE: Could not Setting O_CLOEXEC to file descriptor", __func__, pthread_self(), sesn_ptr, filename);
		}
	}

	struct stat st;
	if (stat(filename, &st)!=0)
	{
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s'}: ERROR: Could not retrieve files's stat", __func__, pthread_self(), sesn_ptr, filename);
		close(fd);
		return OCS_NOT_PROCESSED;
	}

	if (S_ISDIR(st.st_mode))
	{
		close(fd);
		return OCS_NOT_PROCESSED;
	}

	size_t length=st.st_size;

	if (length<(1024*16)) 	use_sendfile=false;// No sendfile for small files

	char etag[_CONFIGDEFAULT_ETAG_SIZE*2];
	GenerateEtag(&st, etag);

	onion_request *request=SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr);
	onion_response *res=SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr);

	const char *range=onion_request_get_header(request, "Range");
	if (range)	strncat(etag, range, sizeof(etag)-1);

	onion_response_set_header(res, "Etag", etag);

	if (range && strncmp(range,"bytes=", 6)==0)
	{
		onion_response_set_code(res, HTTP_PARTIAL_CONTENT);

		char tmp[1024];
		if (strlen(range+6)>=sizeof(tmp))
		{
			close(fd);
			syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s'}: ERROR: BAD RANGE:  SIZE OUT OF PERMESSIBLE LIMIT", __func__, pthread_self(), sesn_ptr, filename);

			return OCS_INTERNAL_ERROR; // Bad specified range. Very bad indeed.
		}


#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', range:'%s'}: Sending a range", __func__, pthread_self(), sesn_ptr, filename, range);
#endif

		strncpy(tmp, range+6, sizeof(tmp)-1);
		char *start=tmp;
		char *end=tmp;
		while (*end!='-' && *end) end++;
		if (*end=='-')
		{
			*end='\0';
			end++;

#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', range:'%s',start:'%s', end:'%s'}: Range boundaries", __func__, pthread_self(), sesn_ptr, filename, range, start, end);
#endif
			size_t ends, starts;
			if (*end)	ends=atol(end);
			else 		ends=length;

			starts=atol(start);
			length=ends-starts+1;
			lseek(fd, starts, SEEK_SET);
			snprintf(tmp,sizeof(tmp),"bytes %d-%d/%d",(unsigned int)starts, (unsigned int)ends, (unsigned int)st.st_size);
			//onion_response_set_header(res, "Accept-Ranges","bytes");
			onion_response_set_header(res, "Content-Range",tmp);
		}
	}//range

	char *mime_type;
	onion_response_set_length(res, length);
	if (IS_PRESENT(attch_ptr) && (*attch_ptr->mime_type))	mime_type=attch_ptr->mime_type;
	else mime_type=onion_mime_get(filename);

	onion_response_set_header(res, "Content-Type", mime_type);

#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', mimeype:'%s', etag:'%s'}: Mime type", __func__, pthread_self(), sesn_ptr, filename, mime_type, etag);
#endif

	const char *prev_etag=onion_request_get_header(request, "If-None-Match");
	if (prev_etag && (strcmp(prev_etag, etag)==0))
	{
#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', mimeype:'%s', etag:'%s'}: If-None-Match: Not modified", __func__, pthread_self(), sesn_ptr, filename, onion_mime_get(filename), etag);
#endif

		onion_response_set_length(res, 0);
		onion_response_set_code(res, HTTP_NOT_MODIFIED);
		onion_response_write_headers(sesn_ptr, res);
		close(fd);

		return OCS_PROCESSED;
	}

	onion_response_write_headers(sesn_ptr, res);
	if ((onion_request_get_flags(request)&OR_HEAD) == OR_HEAD)
	{ // Just head.
		length=0;
	}

	if (length)
	{
#if 1//USE_SENDFILE
		if (use_sendfile)// && request->connection.listen_point->write==(void*)onion_http_write)
		{
			ssize_t r;
			onion_response_write(sesn_ptr, res, NULL, 0);//just flush
			//r=sendfile(/*request->connection.fd*/SESSION_SOCKETFD(sesn_ptr), fd, NULL, length);

			ssize_t	t	= length;
			off_t	ofs = 0;

			while (ofs<t)
			{
					if((r=sendfile(SESSION_SOCKETFD(sesn_ptr), fd, &ofs, t - ofs)) == -1)
					{
						int errno_sendfile=errno;
							if (errno_sendfile==EAGAIN)
							if (errno==EINTR)	continue;
							else 				break;
					}
			}

#ifdef __UF_TESTING
			syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', sendfile_read:'%ld', length:'%lu'}: %s", __func__, pthread_self(), sesn_ptr, filename, r, length, (r==length?"LENGTH MATCH":"LENGTH DONT MATCH"));
#endif
			if (r!=length || r<0)
			{
				syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', err:'%s'}: ERROR: Could not send all file", __func__, pthread_self(), sesn_ptr, filename, strerror(errno));

				close(fd);

				return OCS_INTERNAL_ERROR;
			}

			res->sent_bytes+=length;
			res->sent_bytes_total+=length;
		}
		else
#endif
		{ // Ok, no I cant, do it as always.
			int r=0,w;
			size_t tr=0;
			char tmp[4046];
			if (length>sizeof(tmp))
			{
				size_t max=length-sizeof(tmp);
				while( tr<max )
				{
					r=read(fd, tmp, sizeof(tmp));
					tr+=r;
					if (r<0)
						break;
					w=onion_response_write(sesn_ptr, res, tmp, r);
					if (w!=r)
					{
						//ONION_ERROR("Wrote less than read: write %d, read %d. Quite probably closed connection.",w,r);
						syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', write:'%d', read:'%d'}: ERROR: Wrote less than read: Quite probably closed connection", __func__, pthread_self(), sesn_ptr, filename, w, r);
						break;
					}
				}
			}
			if (sizeof(tmp) >= (length-tr))
			{
				r=read(fd, tmp, length-tr);
				w=onion_response_write(sesn_ptr, res, tmp, r);
				if (w!=r)
				{
					syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', write:'%d', read:'%d'}: ERROR: Wrote less than read: Quite probably closed connection", __func__, pthread_self(), sesn_ptr, filename, w, r);
					//ONION_ERROR("Wrote less than read: write %d, read %d. Quite probably closed connection.",w,r);
				}
			}
		}
	}

	close(fd);
#endif
	return OCS_PROCESSED;
}


/**
 * 	@brief: This is very tied to the http request/response parsing and endpoint handler cycle of the underlying http implementation.
 * 	This function assumes:
 * 	1)the request has been parsed
 * 	2)the handler has been invoked
 * 	So from the implementation's POV this function is logically an extension of the handler and return type must be inline with that.
 * 	For serving up files where the we'd be blocking onwrite to socket, we must keep the connection live, sending "NEED_MOREDATA" won't help
 * 	(which is the case for client upload ie other direction) because that is only read prior to the invocation of the handler.
 * 	So we set OR_RES_SENDFILE_INROGRESS in 'res' to force it to keep the  connection running and get
 * 	a nudge from epoll for when the next write is available.
 */
int
InitialiseSendFileContext (Session *sesn_ptr, const char *filename, AttachmentDescriptor *attch_ptr)
{
	if (unlikely(IS_EMPTY(filename))) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Filename");
		return OCS_NOT_PROCESSED;
	}

	int fd = open(filename, O_RDONLY|O_CLOEXEC);

	if (fd < 0) {
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: ERROR: COULD NOT OPEN OPEN FILE...", __func__, pthread_self(), sesn_ptr, filename);
		return OCS_NOT_PROCESSED;
	}

	if (O_CLOEXEC == 0) {
		int flags = fcntl(fd, F_GETFD);

		if (flags == -1) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: NOTICE: Could not Rrtrieving flags from file descriptor", __func__, pthread_self(), sesn_ptr, filename);
		}

		flags |= FD_CLOEXEC;
		if (fcntl(fd, F_SETFD, flags) == -1) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', file:'%s'}: NOTICE: Could not Setting O_CLOEXEC to file descriptor", __func__, pthread_self(), sesn_ptr, filename);
		}
	}

	struct stat st;
	if (stat(filename, &st) != 0) {
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s'}: ERROR: Could not retrieve files's stat", __func__, pthread_self(), sesn_ptr, filename);
		close(fd);

		return OCS_NOT_PROCESSED;
	}

	if (S_ISDIR(st.st_mode))
	{
		close(fd);
		return OCS_NOT_PROCESSED;
	}

	size_t length = st.st_size;

	char etag[_CONFIGDEFAULT_ETAG_SIZE*2];
	GenerateEtag(&st, etag);

	onion_request 	*request=SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr);
	onion_response 	*res=SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr);

	const char *range=onion_request_get_header(request, "Range");
	if (range)	strncat(etag, range, sizeof(etag)-1);

	onion_response_set_header(res, "Etag", etag);

	if (range && strncmp(range,"bytes=", 6) == 0) {
		onion_response_set_code(res, HTTP_PARTIAL_CONTENT);

		char tmp[1024];
		if (strlen(range+6) >= sizeof(tmp)) {
			close(fd);
			syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s'}: ERROR: BAD RANGE:  SIZE OUT OF PERMESSIBLE LIMIT", __func__, pthread_self(), sesn_ptr, filename);

			return OCS_INTERNAL_ERROR; // Bad specified range. Very bad indeed.
		}


#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', range:'%s'}: Sending a range", __func__, pthread_self(), sesn_ptr, filename, range);
#endif

		strncpy(tmp, range + 6, sizeof(tmp) - 1);
		char *start = tmp;
		char *end = tmp;
		while (*end != '-' && *end) end++;
		if (*end == '-') {
			*end = '\0';
			end++;

#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', range:'%s',start:'%s', end:'%s'}: Range boundaries", __func__, pthread_self(), sesn_ptr, filename, range, start, end);
#endif
			size_t ends, starts;
			if (*end)	ends = atol(end);
			else 		ends = length;

			starts = atol(start);
			length = ends - starts + 1;
			lseek(fd, starts, SEEK_SET);
			snprintf(tmp,sizeof(tmp),"bytes %d-%d/%d",(unsigned int)starts, (unsigned int)ends, (unsigned int)st.st_size);
			//onion_response_set_header(res, "Accept-Ranges","bytes");
			onion_response_set_header(res, "Content-Range",tmp);
		}
	}//range


	const char *mime_type;
	onion_response_set_length(res, length);
	if (IS_PRESENT(attch_ptr) && (*attch_ptr->mime_type))	mime_type=attch_ptr->mime_type;
	else 																									mime_type=onion_mime_get(filename);

	onion_response_set_header(res, "Content-Type", mime_type);

#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', mimeype:'%s', etag:'%s'}: Mime type", __func__, pthread_self(), sesn_ptr, filename, mime_type, etag);
#endif

	const char *prev_etag = onion_request_get_header(request, "If-None-Match");
	if (prev_etag && (strcmp(prev_etag, etag) == 0))
	{
#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', filename:'%s', mimeype:'%s', etag:'%s'}: If-None-Match: Not modified", __func__, pthread_self(), sesn_ptr, filename, onion_mime_get(filename), etag);
#endif

		onion_response_set_length(res, 0);
		onion_response_set_code(res, HTTP_NOT_MODIFIED);
		onion_response_write_headers(sesn_ptr, res);
		close(fd);

		return OCS_PROCESSED;
	}

	onion_response_write_headers(sesn_ptr, res);
	if ((onion_request_get_flags(request)&OR_HEAD) == OR_HEAD)
	{ // Just head.
		//length=0;
		close(fd);
		return OCS_PROCESSED;
	}

	SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd=fd;
	SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_size=st.st_size;
	sesn_ptr->ssptr->socket_msg_out.processed_msg_size=st.st_size;//use as rolling offset
	sesn_ptr->ssptr->socket_msg_out.written_msg_size=0;
	res->flags|=OR_RES_SENDFILE_INROGRESS;

	//onion_response_write_headers(sesn_ptr, res);
	onion_response_write(sesn_ptr, res, NULL, 0);//just flush

	return (HttpSendFile(sesn_ptr));

}


onion_connection_status HttpSendFile (Session *sesn_ptr)
{
	bool use_sendfile=true;

	//if (length<(1024*16)) 	use_sendfile=false;// No sendfile for small files

	int 						fd			=SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_fd;
	ssize_t					t				=SESSION_HTTPSESN_SENDFILECTX(sesn_ptr).file_size;
	onion_request 	*request=SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr);
	onion_response 	*res		=SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr);
	bool						blocking_write=false;

	if (use_sendfile)
	{
		ssize_t r;
		//onion_response_write(sesn_ptr, res, NULL, 0);//just flush

		off_t	ofs = sesn_ptr->ssptr->socket_msg_out.written_msg_size;

		while (ofs<t)
		{
			r=sendfile(SESSION_SOCKETFD(sesn_ptr), fd, &ofs, t - ofs);
			int errno_sendfile=errno;

			if (r>0)
			{
				sesn_ptr->ssptr->socket_msg_out.written_msg_size+=r;
#if __UF_TESTING
				syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', sendfile_written:'%ld', total_written_msg_sz:'%lu', file_sz:'%lu'}: Read outcome: %s", __func__, pthread_self(), sesn_ptr, r, sesn_ptr->ssptr->socket_msg_out.written_msg_size, t, (r==t?"SENT FULL":"SENT PARTIAL"));
#endif
			}
			else if (r==-1)
			{
				//https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c725bfce7968009756ed2836a8cd7ba4dc163011
				//on linux 4.3+ sendfile behaviour changed: it can be now be interrupted in the middle of transmission, and that's indistinguishable from a normal blocking on the socket buffer
				if (errno_sendfile==EAGAIN || errno_sendfile==EINTR)
				{
#if __UF_TESTING
				syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', sendfile_written:'%ld', total_written_msg_sz:'%lu', file_sz:'%lu', errno:'%d'}: Read outcome: WOULD BLOCK OR INTERRUPTED: ", __func__, pthread_self(), sesn_ptr, r, sesn_ptr->ssptr->socket_msg_out.written_msg_size, t, errno_sendfile);
#endif

					SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLEREQUEST);
					blocking_write=true;
				}
				break;

				//if (errno==EINTR)	continue;
			}
		}//while

		if (r>0)
		{
			if (sesn_ptr->ssptr->socket_msg_out.written_msg_size==t)
			{
#ifdef __UF_TESTING
				syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', sendfile_written:'%ld', total_written_msg_sz:'%lu', file_sz:'%lu'}: Finished sending file...", __func__, pthread_self(), sesn_ptr, r, sesn_ptr->ssptr->socket_msg_out.written_msg_size, t);
#endif
				close(fd);

				res->sent_bytes=r;
				res->sent_bytes_total+=r;

				return OCS_PROCESSED;
			}
			else
			{
				return OCS_NEED_MORE_DATA;
			}
		}
		else
		{
			if (blocking_write)	return OCS_NEED_MORE_DATA;

#ifdef __UF_TESTING
				syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', sendfile_written:'%ld', total_written_msg_sz:'%lu', file_sz:'%lu' err:'%s'}: ERROR: Sesing file", __func__, pthread_self(), sesn_ptr, r, sesn_ptr->ssptr->socket_msg_out.written_msg_size, t, strerror(errno));
#endif

			close(fd);
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR);

			return OCS_INTERNAL_ERROR;
		}
	}
	else
	{
#if 0 //mostly there...
		int r=0,w;
		size_t tr=0;
		char tmp[4046];
		if (length>sizeof(tmp))
		{
			size_t max=length-sizeof(tmp);
			while( tr<max )
			{
				r=read(fd, tmp, sizeof(tmp));
				tr+=r;
				if (r<0)
					break;
				w=onion_response_write(sesn_ptr, res, tmp, r);
				if (w!=r)
				{
					//ONION_ERROR("Wrote less than read: write %d, read %d. Quite probably closed connection.",w,r);
					syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', write:'%d', read:'%d'}: ERROR: Wrote less than read: Quite probably closed connection", __func__, pthread_self(), sesn_ptr, filename, w, r);
					break;
				}
			}
		}
		if (sizeof(tmp) >= (length-tr))
		{
			r=read(fd, tmp, length-tr);
			w=onion_response_write(sesn_ptr, res, tmp, r);
			if (w!=r)
			{
				syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', filename:'%s', write:'%d', read:'%d'}: ERROR: Wrote less than read: Quite probably closed connection", __func__, pthread_self(), sesn_ptr, filename, w, r);
			}
		}
#endif
	}//non-sendfile

	close(fd);

	return OCS_PROCESSED;
}
