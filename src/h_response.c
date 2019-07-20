/*
	Onion HTTP server library
	Copyright (C) 2010-2016 David Moreno Montero and others

	This library is free software; you can redistribute it and/or
	modify it under the terms of, at your choice:

	a. the Apache License Version 2.0.

	b. the GNU General Public License as published by the
		Free Software Foundation; either version 2.0 of the License,
		or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of both libraries, if not see
	<http://www.gnu.org/licenses/> and
	<http://www.apache.org/licenses/LICENSE-2.0>.
	*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <assert.h>
#include <utils.h>
#include <dictionary.h>
#include <codecs.h>
#include <request.h>
#include <response.h>
#include <http_request_handler.h>
#include <vector.h>
#include <http_session_type.h>
#include <protocol_http_io.h>


/// @defgroup response Response. Write response data to client: headers, content body...

const char *onion_response_code_description(int code);

// DONT_USE_DATE_HEADER is not defined anywhere, but here just in case needed in the future.

#ifndef DONT_USE_DATE_HEADER
static volatile time_t onion_response_last_time=0;
static char *onion_response_last_date_header=NULL;
#ifdef HAVE_PTHREADS
pthread_rwlock_t onion_response_date_lock=PTHREAD_RWLOCK_INITIALIZER;
#endif
#endif


/* @short Generates a new response object
 * @memberof onion_response_t
 * @ingroup response
 *
 * This response is generated from a request, and gets from there the writer and writer data.
 *
 * Also fills some important data, as server Id, License type, and the default content type.
 *
 * Default content type is HTML, as normally this is what is needed. This is nontheless just
 * the default, and can be changed to any other with a call to:
 *
 *   onion_response_set_header(res, "Content-Type", my_type);
 *
 * The response object must be freed with onion_response_free, which also returns the keep alive
 * status.
 *
 * onion_response objects are passed by onion internally to process the request, and should not be
 * created by user normally. Nontheless the option exist.
 *
 * @returns An onion_response object for that request.
 */
onion_response *onion_response_initialise(Session *sesn_ptr)
 {
	//onion_response *res=malloc(sizeof(onion_response));
	 onion_response *res=SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr);
	 onion_request *req=SESSION_HTTPSESN_REQUEST_PTR(sesn_ptr);

	res->request=req;
	res->headers=onion_dict_new();
	res->code=200; // The most normal code, so no need to overwrite it in other codes.
	res->flags=0;
	res->sent_bytes_total=res->length=res->sent_bytes=0;
	res->buffer_pos=0;

#ifndef DONT_USE_DATE_HEADER
	{
		time_t t;
		struct tm tmp;

		t = time(NULL);

		// onion_response_last_date_header is set to t later. It should be more or less atomic.
		// If not no big deal, as we will just use slightly more CPU on those "ephemeral" moments.

		time_t current = __sync_add_and_fetch(&onion_response_last_time, 0);

		if (t!=current){
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s: Recalculating date header", __func__);
#endif
			char current_datetime[200];

			if(localtime_r(&t, &tmp) == NULL) {
					perror("localtime");
					exit(EXIT_FAILURE);
			}

			if (strftime(current_datetime, sizeof(current_datetime), "%a, %d %b %Y %H:%M:%S %Z", &tmp) == 0) {
					fprintf(stderr, "strftime returned 0");
					exit(EXIT_FAILURE);
			}
#ifdef HAVE_PTHREADS
			pthread_rwlock_wrlock(&onion_response_date_lock);
#endif
			__sync_bool_compare_and_swap(&onion_response_last_time, current, t);
			if (onion_response_last_date_header)
				free(onion_response_last_date_header);
			onion_response_last_date_header=mystrdup(current_datetime);
#ifdef HAVE_PTHREADS
			pthread_rwlock_unlock(&onion_response_date_lock);
#endif
		}
	}
#ifdef HAVE_PTHREADS
	pthread_rwlock_rdlock(&onion_response_date_lock);
#endif
	assert(onion_response_last_date_header);
	onion_dict_add(res->headers, "Date", onion_response_last_date_header, OD_DUP_VALUE);
#ifdef HAVE_PTHREADS
	pthread_rwlock_unlock(&onion_response_date_lock);
#endif
#endif // USE_DATE_HEADER
	// Sorry for the advertisment.
	onion_dict_add(res->headers, "Server", "ufsrv", 0);
	onion_dict_add(res->headers, "Content-Type", "text/html", 0); // Maybe not the best guess, but really useful.
	//time_t t=time(NULL);
	//onion_dict_add(res->headers, "Date", asctime(localtime(&t)), OD_DUP_VALUE);

	//AA+ to help with object state processing, since it is statically allocated
	res->flags|=OR_RES_INITIALISED;

	return res;
}

#if 0

/**
 * @short Generates a new response object
 * @memberof onion_response_t
 * @ingroup response
 *
 * This response is generated from a request, and gets from there the writer and writer data.
 *
 * Also fills some important data, as server Id, License type, and the default content type.
 *
 * Default content type is HTML, as normally this is what is needed. This is nontheless just
 * the default, and can be changed to any other with a call to:
 *
 *   onion_response_set_header(res, "Content-Type", my_type);
 *
 * The response object must be freed with onion_response_free, which also returns the keep alive
 * status.
 *
 * onion_response objects are passed by onion internally to process the request, and should not be
 * created by user normally. Nontheless the option exist.
 *
 * @returns An onion_response object for that request.
 */
onion_response *onion_response_new(onion_request *req){
	onion_response *res=malloc(sizeof(onion_response));

	res->request=req;
	res->headers=onion_dict_new();
	res->code=200; // The most normal code, so no need to overwrite it in other codes.
	res->flags=0;
	res->sent_bytes_total=res->length=res->sent_bytes=0;
	res->buffer_pos=0;

#ifndef DONT_USE_DATE_HEADER
	{
		time_t t;
		struct tm tmp;

		t = time(NULL);

		// onion_response_last_date_header is set to t later. It should be more or less atomic.
		// If not no big deal, as we will just use slightly more CPU on those "ephemeral" moments.

		time_t current = __sync_add_and_fetch(&onion_response_last_time, 0);

		if (t!=current){
			syslog(LOG_DEBUG, "%s: Recalculating date header", __func__);
			char current_datetime[200];

			if(localtime_r(&t, &tmp) == NULL) {
					perror("localtime");
					exit(EXIT_FAILURE);
			}

			if (strftime(current_datetime, sizeof(current_datetime), "%a, %d %b %Y %H:%M:%S %Z", &tmp) == 0) {
					fprintf(stderr, "strftime returned 0");
					exit(EXIT_FAILURE);
			}
#ifdef HAVE_PTHREADS
			pthread_rwlock_wrlock(&onion_response_date_lock);
#endif
			__sync_bool_compare_and_swap(&onion_response_last_time, current, t);
			if (onion_response_last_date_header)
				free(onion_response_last_date_header);
			onion_response_last_date_header=mystrdup(current_datetime);
#ifdef HAVE_PTHREADS
			pthread_rwlock_unlock(&onion_response_date_lock);
#endif
		}
	}
#ifdef HAVE_PTHREADS
	pthread_rwlock_rdlock(&onion_response_date_lock);
#endif
	assert(onion_response_last_date_header);
	onion_dict_add(res->headers, "Date", onion_response_last_date_header, OD_DUP_VALUE);
#ifdef HAVE_PTHREADS
	pthread_rwlock_unlock(&onion_response_date_lock);
#endif
#endif // USE_DATE_HEADER
	// Sorry for the advertisment.
	onion_dict_add(res->headers, "Server", "ufsrv", 0);
	onion_dict_add(res->headers, "Content-Type", "text/html", 0); // Maybe not the best guess, but really useful.
	//time_t t=time(NULL);
	//onion_dict_add(res->headers, "Date", asctime(localtime(&t)), OD_DUP_VALUE);

	return res;
}
#endif

/**
 *	@brief: pure memory management for the response object, as opposed to free below which connection semantics involved
 *
 */
void onion_response_destruct(Session *sesn_ptr)
{
	// write pending data.

	//AA+ flag set by initialise response
	if (!(SESSION_HTTPSESN_RESPONSE(sesn_ptr).flags&OR_RES_INITIALISED)) {//!(res->flags&OR_RES_INITIALISED))
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (cid: '%lu'): RESPONSE OBJECT WAS NOT INITIALISED: NOT RESETING...", __func__, SESSION_ID(sesn_ptr));
#endif
		return;
	}

	onion_dict_free(SESSION_HTTPSESN_RESPONSE(sesn_ptr).headers);

	SESSION_HTTPSESN_RESPONSE(sesn_ptr).flags=0;

	//AA- we don't kill as it is ot pointer
	//free(res);

	return ;
}


/**
 * @short Frees the memory consumed by this object
 * @memberof onion_response_t
 * @ingroup response
 *
 * This function returns the close status: OR_KEEP_ALIVE or OR_CLOSE_CONNECTION as needed.
 *
 * @returns Whether the connection should be closed or not, or an error status to be handled by server.
 * @see onion_connection_status
 */
onion_connection_status onion_response_free(Session *sesn_ptr, onion_response *res)
{
	// write pending data.

	//AA+ flag set by initialise response
	if (!(res->flags&OR_RES_INITIALISED)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (cid: '%lu'): RESPONSE OBJECT WAS NOT INITIALISED: NOT RESETING...", __func__, SESSION_ID(sesn_ptr));
#endif

		return OCS_CLOSE_CONNECTION;
	}

	if (!(res->flags&OR_HEADER_SENT) && res->buffer_pos<sizeof(res->buffer))
		onion_response_set_length(res, res->buffer_pos);

	//TODO: modify write
	if (!(res->flags&OR_HEADER_SENT))
		onion_response_write_headers(sesn_ptr, res);

	onion_response_flush(sesn_ptr, res);
	onion_request *req=res->request;

	if (res->flags&OR_CHUNKED) { // Set the chunked data end.
		//AA-
		//req->connection.listen_point->write(req, "0\r\n\r\n",5);

		HttpSendMessage (sesn_ptr, "0\r\n\r\n", 5);
	}

	int r=OCS_CLOSE_CONNECTION;

	//this comment is not applicable when code below is enabled
	//AA+ we do this check as a stand-alone request in IsConnectionKeepAlive(). In the interested of keeping this function
	//focused on data management only, this check is now done as input into the decision whether to close connection or or not after successful PROCESSED return

#if 1
	// it is a rare occasion that there is no request, but although unlikely, it may happen
	if (req)
	{
		// keep alive only on HTTP/1.1.
		syslog(LOG_DEBUG, "%s: keep alive [req wants] %d && ([SENDFILE] %d || [skip] %d || [lenght ok] %d==%d || [chunked] %d)", __func__,
								onion_request_keep_alive(req), res->flags&OR_RES_SENDFILE_INROGRESS, res->flags&OR_SKIP_CONTENT,res->length, res->sent_bytes, res->flags&OR_CHUNKED);

		if (
				(res->flags&OR_RES_SENDFILE_INROGRESS) ||
				((onion_request_keep_alive(req)) && ((res->flags&OR_SKIP_CONTENT) || (res->length==res->sent_bytes) || (res->flags&OR_CHUNKED)))
			 )
			r=OCS_KEEP_ALIVE;
	}
#endif

	onion_response_destruct(sesn_ptr);
	//AA-
	//onion_dict_free(res->headers);

	//AA- we don't kill as it is ot pointer
	//free(res);

	return r;
}


/**
 * @short Adds a header to the response object
 * @memberof onion_response_t
 * @ingroup response
 */
void onion_response_set_header(onion_response *res, const char *key, const char *value) {
#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s: Adding header %s = %s", __func__, key, value);
#endif
	onion_dict_add(res->headers, key, value, OD_DUP_ALL|OD_REPLACE); // DUP_ALL not so nice on memory side...
}

/**
 * @short Sets the header length. Normally it should be through set_header, but as its very common and needs some procesing here is a shortcut
 * @memberof onion_response_t
 * @ingroup response
 */
void onion_response_set_length(onion_response *res, size_t len){
	if (len!=res->sent_bytes && res->flags&OR_HEADER_SENT){
		syslog(LOG_DEBUG, "Trying to set length after headers sent. Undefined onion behaviour.");
		return;
	}
	char tmp[16];
	sprintf(tmp,"%lu",(unsigned long)len);
	onion_response_set_header(res, "Content-Length", tmp);
	res->length=len;
	res->flags|=OR_LENGTH_SET;
}

/**
 * @short Sets the return code
 * @memberof onion_response_t
 * @ingroup response
 */
void onion_response_set_code(onion_response *res, int  code){
	res->code=code;
}

static void write_header(Session *sesn_ptr, /*onion_response *res,*/ const char *key, const char *value, int flags);
/**
 * @short Helper that is called on each header, and writes the header
 * @memberof onion_response_t
 * @ingroup response
 */
static void write_header(Session *sesn_ptr, /*onion_response *res,*/ const char *key, const char *value, int flags){
	//ONION_DEBUG0("Response header: %s: %s",key, value);

	onion_response_write0(sesn_ptr, SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr)/*res*/, key);
	onion_response_write(sesn_ptr, SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr)/*res*/, ": ",2);
	onion_response_write0(sesn_ptr, SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr)/*res*/, value);
	onion_response_write(sesn_ptr, SESSION_HTTPSESN_RESPONSE_PTR(sesn_ptr)/*res*/, "\r\n",2);
}

#define CONNECTION_CLOSE 			"Connection: Close\r\n"
#define CONNECTION_KEEP_ALIVE 		"Connection: Keep-Alive\r\n"
#define CONNECTION_CHUNK_ENCODING 	"Transfer-Encoding: chunked\r\n"
#define CONNECTION_UPGRADE 			"Connection: Upgrade\r\n"

/**
 * @short Writes all the header to the given response
 * @memberof onion_response_t
 * @ingroup response
 *
 * It writes the headers and depending on the method, return OR_SKIP_CONTENT. this is set when in head mode. Handlers
 * should react to this return by not trying to write more, but if they try this object will just skip those writtings.
 *
 * Explicit calling to this function is not necessary, as as soon as the user calls any write function this will
 * be performed.
 *
 * As soon as the headers are written, any modification on them will be just ignored.
 *
 * @returns 0 if should procced to normal data write, or OR_SKIP_CONTENT if should not write content.
 */
int onion_response_write_headers(Session *sesn_ptr, onion_response *res){
	if (!res->request){
		syslog(LOG_DEBUG, "Bad formed response. Need a request at creation. Will not write headers.");
		return -1;
	}

	res->flags|=OR_HEADER_SENT; // I Set at the begining so I can do normal writing.
	res->request->flags|=OR_HEADER_SENT;
	char chunked=0;

	if (res->request->flags&OR_HTTP11){
		onion_response_printf(sesn_ptr, res, "HTTP/1.1 %d %s\r\n",res->code, onion_response_code_description(res->code));
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "Response header: HTTP/1.1 %d %s",res->code, onion_response_code_description(res->code));
#endif

		if (!(res->flags&OR_LENGTH_SET)  && onion_request_keep_alive(res->request)){
			onion_response_write(sesn_ptr, res, CONNECTION_CHUNK_ENCODING, sizeof(CONNECTION_CHUNK_ENCODING)-1);
			chunked=1;
		}
	} else	{
		onion_response_printf(sesn_ptr, res, "HTTP/1.0 %d %s\r\n",res->code, onion_response_code_description(res->code));
		if (res->flags&OR_LENGTH_SET) // On HTTP/1.0, i need to state it. On 1.1 it is default.
			onion_response_write(sesn_ptr, res, CONNECTION_KEEP_ALIVE, sizeof(CONNECTION_KEEP_ALIVE)-1);
	}

	if (!(res->flags&OR_LENGTH_SET) && !chunked && !(res->flags&OR_CONNECTION_UPGRADE))
		onion_response_write(sesn_ptr, res, CONNECTION_CLOSE, sizeof(CONNECTION_CLOSE)-1);

	if (res->flags&OR_CONNECTION_UPGRADE)
		onion_response_write(sesn_ptr, res, CONNECTION_UPGRADE, sizeof(CONNECTION_UPGRADE)-1);

	onion_dict_preorder(res->headers, write_header, sesn_ptr);//res);

	if (res->request->session_id && (onion_dict_count(res->request->session)>0)) // I have session with something, tell user
		onion_response_printf(sesn_ptr, res, "Set-Cookie: sessionid=%s; httponly; Path=/\n", res->request->session_id);

	onion_response_write(sesn_ptr, res,"\r\n",2);

	//syslog(LOG_DEBUG, "Headers written");
	res->sent_bytes=-res->buffer_pos; // the header size is not counted here. It will add again so start negative.

	if ((res->request->flags&OR_METHODS)==OR_HEAD){
		onion_response_flush(sesn_ptr, res);
		res->flags|=OR_SKIP_CONTENT;
		return OR_SKIP_CONTENT;
	}
	if (chunked){
		onion_response_flush(sesn_ptr, res);
		res->flags|=OR_CHUNKED;
	}

	return 0;
}

/**
 * @short Write some response data.
 * @memberof onion_response_t
 * @ingroup response
 *
 * This is the main write data function. If the headers have not been sent yet, they are now.
 *
 * It's internally used also by the write0 and printf versions.
 *
 * Also it does some buffering, so data is not sent as written by code, but only in chunks.
 * These chunks are when the response is finished, or when the internal buffer is full. This
 * helps performance, and eases the programming on the user side.
 *
 * If length is 0, forces the write of pending data.
 *
 * @returns The bytes written, normally just length. On error returns OCS_CLOSE_CONNECTION.
 */
ssize_t onion_response_write(Session *sesn_ptr, onion_response *res, const char *data, size_t length)
{
	if (res->flags&OR_SKIP_CONTENT) {
		if (!(res->flags&OR_HEADER_SENT)){ // Automatic header write
			onion_response_write_headers(sesn_ptr, res);
		}
		syslog(LOG_DEBUG, "%s (cid:'%lu'): Skipping content as we are in HEAD mode", __func__, SESSION_ID(sesn_ptr));
		return OCS_CLOSE_CONNECTION;
	}

	if (length == 0) {
		onion_response_flush(sesn_ptr, res);
		return 0;
	}

	//syslog(LOG_DEBUG, "%s (cid:'%lu'): Buffering %lu bytes. Buffer position: '%ld' [%u total sent] (%p)", __func__, SESSION_ID(sesn_ptr),
		//	length, res->buffer_pos, res->sent_bytes, res);

	int l = length;
	int w = 0;

	//we are over capacity
	while (res->buffer_pos + l > sizeof(res->buffer)) {
		int wb = sizeof(res->buffer) - res->buffer_pos; //get available capacity in the buf, could be less than length
		syslog(LOG_DEBUG, "%s (cid:'%lu'): BUFFER OVER CAPACITY: buffer position: '%lu'. AMOUNT TO BE COPIED: '%d' ", __func__, SESSION_ID(sesn_ptr), res->buffer_pos, wb);
		memcpy(&res->buffer[res->buffer_pos], data, wb);//copy exactly to calculated capacity

		res->buffer_pos = sizeof(res->buffer);//
		if (onion_response_flush(sesn_ptr, res) < 0)
			return w;//could be zeero

		l -= wb;//if 0 , we wrtitten the full lot, we have some left over due to have reached buffer capacity
		data += wb;
		w += wb;//update how much we have written so far
	}

	//if we have left over, copy to buffer

	memcpy(&res->buffer[res->buffer_pos], data, l);
	res->buffer_pos += l;
	w += l;

	return w;
}

/**
 * @short Writes all buffered output waiting for sending.
 * @ingroup response
 *
 * If header has not been sent yet (delayed), it uses a temporary buffer to send it now. This
 * way header can use the buffer_size information to send the proper content-length, even when it
 * wasnt properly set by programmer. Whith this information its possib to keep alive the connection
 * on more cases.
 *	AA+
 * 	@return: <0 on error
 * 	0 blokcing
 * 	+1 on success
 */
int onion_response_flush(Session *sesn_ptr, onion_response *res)
{
	res->sent_bytes+=res->buffer_pos;
	res->sent_bytes_total+=res->buffer_pos;

	if(res->buffer_pos==0) // Not used.
		return 0;

	if (!(res->flags&OR_HEADER_SENT))
	{ // Automatic header write

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): Doing fast header hack: store current buffer, send current headers. Resend buffer.", __func__, SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr));
#endif

		char tmpb[sizeof(res->buffer)];
		int tmpp=res->buffer_pos;
		memcpy(tmpb, res->buffer, res->buffer_pos);
		res->buffer_pos=0;

		onion_response_write_headers(sesn_ptr, res);
		onion_response_write( sesn_ptr, res, tmpb, tmpp );

		return 1;//return 0;
	}

	if (res->flags&OR_SKIP_CONTENT) // HEAD request
		return 1;//return 0;

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "Flushing: %ld bytes", res->buffer_pos);
#endif

	onion_request *req=res->request;

	//AA- use write function
	//ssize_t (*write)(onion_request *, const char *data, size_t len);
	//write=req->connection.listen_point->write;

	ssize_t w;
	off_t pos=0;
	//ONION_DEBUG0("Write %d bytes",res->buffer_pos);
	if (res->flags&OR_CHUNKED)
	{
		char tmp[16];
		snprintf(tmp,sizeof(tmp),"%X\r\n",(unsigned int)res->buffer_pos);
		//if ( (w=write(req, tmp, strlen(tmp)))<=0){
		if ( (w=HttpSendMessage (sesn_ptr, tmp, strlen(tmp)))<0)
		{ //not '<0' as opposed to '<=0'
			syslog(LOG_DEBUG, "%s: Error writing chunk encoding length. Aborting write.", __func__);
			return OCS_CLOSE_CONNECTION;
		}
		syslog(LOG_DEBUG, "%s: Write %ld-%ld bytes", __func__, res->buffer_pos,w);
	}

	if ((w=HttpSendMessage (sesn_ptr, &res->buffer[pos], res->buffer_pos))<0)
	{ //not '<0' as opposed to '<=0'
		syslog(LOG_DEBUG, "%s: Error writing chunk encoding length. Aborting write.", __func__);
		return OCS_CLOSE_CONNECTION;
	}

	//AA+ necessary to to prevent duplicate output of the same buffer
	res->buffer_pos=0;

#if 0
	//while ( (w=write(req, &res->buffer[pos], res->buffer_pos)) != res->buffer_pos){
	while ( (w=write(req, &res->buffer[pos], res->buffer_pos)) != res->buffer_pos)
	{
		if (w<=0 || res->buffer_pos<0){
			syslog(LOG_DEBUG, "%s: Error writing %ld bytes. Maybe closed connection. Code %ld. ",__func__, res->buffer_pos, w);
			perror("");
			res->buffer_pos=0;
			return OCS_CLOSE_CONNECTION;
		}
		pos+=w;
		syslog(LOG_DEBUG, "%s: Write %ld-%ld bytes", __func__, res->buffer_pos,w);
		res->buffer_pos-=w;
	}
#endif

	//TODO: this was causing issues with serving up files to clients: adds 2 extra bytes \r\n and messes up downloaded files for clients
	/*if ( (w=HttpSendMessage (sesn_ptr, "\r\n", 2))<0)
	{ //not '<0' as opposed to '<=0'
		syslog(LOG_DEBUG, "%s: Error writing end of chunk encoding length. Aborting write.", __func__);
		return OCS_CLOSE_CONNECTION;
	}
	//AA+ necessary to to prevent duplicate output of the same buffer
	res->buffer_pos=0;*/

#if 0
	if (res->flags&OR_CHUNKED)
	{
		write(req,"\r\n",2);
	}

	res->buffer_pos=0;
#endif

	//return 0;//AA-
	return 1;//
}


/// Writes a 0-ended string to the response.
/// @ingroup response
ssize_t onion_response_write0(Session *sesn_ptr, onion_response *res, const char *data){
	return onion_response_write(sesn_ptr, res, data, strlen(data));
}

/**
 * @short Writes the given string to the res, but encodes the data using html entities
 * @ingroup response
 *
 * The encoding mens that <code><html> whould become &lt;html&gt;</code>
 */
ssize_t onion_response_write_html_safe(Session *sesn_ptr, onion_response *res, const char *data){
	char *tmp=onion_html_quote(data);
	if (tmp){
		int r=onion_response_write0(sesn_ptr, res, tmp);
		free(tmp);
		return r;
	}
	else
		return onion_response_write0(sesn_ptr, res, data);
}


/**
 * @short Writes some data to the response. Using sprintf format strings.
 * @memberof onion_response_t
 * @ingroup response
 */
ssize_t onion_response_printf(Session *sesn_ptr, onion_response *res, const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	ssize_t ret=onion_response_vprintf(sesn_ptr, res, fmt, ap);
	va_end(ap);
	return ret;
}

/**
 * @short Writes some data to the response. Using sprintf format strings. va_list args version
 * @ingroup response
 *
 * @param args va_list of arguments
 * @memberof onion_response_t
 */
ssize_t onion_response_vprintf(Session *sesn_ptr, onion_response *res, const char *fmt, va_list args)
{
	char temp[512];
	va_list argz;
	int l;
	va_copy(argz, args);
	l=vsnprintf(temp, sizeof(temp), fmt, argz);
	va_end(argz);
	if (l<0) {
		syslog(LOG_DEBUG, "Invalid vprintf fmt");
		return -1;
	}
	else if (l<sizeof(temp)) {
		return onion_response_write(sesn_ptr, res, temp, l);
	}
	else {
		ssize_t s;
		char*buf = malloc(l+1);
		if (!buf){
		  // this cannot happen, since onion_low_scalar_malloc
		  // handles that error...
			syslog(LOG_DEBUG, "%s: Could not reserve %d bytes", __func__, l+1);
			return -1;
		}
		vsnprintf(buf, l+1, fmt, args);
		s = onion_response_write (sesn_ptr, res, buf, l);
		free (buf);
		return s;
	}
}




/**
 * @short Returns a const char * string with the code description.
 * @memberof onion_response_t
 * @ingroup response
 */
const char *onion_response_code_description(int code){
	switch(code){
		case HTTP_OK:
			return "OK";
		case HTTP_CREATED:
			return "Created";
		case HTTP_PARTIAL_CONTENT:
			return "Partial Content";
		case HTTP_MULTI_STATUS:
			return "Multi-Status";

		case HTTP_SWITCH_PROTOCOL:
			return "Switching Protocols";

		case HTTP_MOVED:
			return "Moved Permanently";
		case HTTP_REDIRECT:
			return "Found";
		case HTTP_SEE_OTHER:
			return "See Other";
		case HTTP_NOT_MODIFIED:
			return "Not Modified";
		case HTTP_TEMPORARY_REDIRECT:
			return "Temporary Redirect";

		case HTTP_BAD_REQUEST:
			return "Bad Request";
		case HTTP_UNAUTHORIZED:
			return "Unauthorized";
		case HTTP_FORBIDDEN:
			return "Forbidden";
		case HTTP_NOT_FOUND:
			return "Not Found";
		case HTTP_METHOD_NOT_ALLOWED:
			return "Method Not Allowed";

		case HTTP_INTERNAL_ERROR:
			return "Internal Server Error";
		case HTTP_NOT_IMPLEMENTED:
			return "Not Implemented";
		case HTTP_BAD_GATEWAY:
			return "Bad Gateway";
		case HTTP_SERVICE_UNAVAILABLE:
			return "Service Unavailable";
	}
	return "CODE UNKNOWN";
}


/**
 * @short Returns the headers dictionary, so user can add repeated headers
 * @ingroup response
 *
 * Only simple use case is to add several coockies; using normal set_header is not possible,
 * but accessing the dictionary user can add repeated headers without problem.
 */
onion_dict *onion_response_get_headers(onion_response *res){
	return res->headers;
}


/**
 * @short Sets a new cookie into the response.
 * @ingroup response
 *
 * @param res Response object
 * @param cookiename Name for the cookie
 * @param cookievalue Value for the cookis
 * @param validity_t Seconds this cookie is valid (added to current datetime). -1 to do not expire, 0 to expire inmediatly.
 * @param path Cookie valid only for this path
 * @param Domain Cookie valid only for this domain (www.example.com, or *.example.com).
 * @param flags Flags from onion_cookie_flags_t, for example OC_SECURE or OC_HTTP_ONLY
 *
 *
 * If validity is 0, cookie is set to expire right now.
 */
void onion_response_add_cookie(onion_response *res, const char *cookiename, const char *cookievalue, time_t validity_t, const char *path, const char *domain, int flags){
	char data[512];
	int pos;
	pos=snprintf(data,sizeof(data),"%s=%s",cookiename, cookievalue);
	if (validity_t==0)
		pos+=snprintf(data+pos, sizeof(data)-pos, "; expires=Thu, 01 Jan 1970 00:00:00 GMT");
	else if (validity_t>0){
		struct tm *tmp;
		time_t t=time(NULL) + validity_t;
		tmp = localtime(&t);
		pos+=strftime(data+pos, sizeof(data)-pos, "; expires=%a, %d %b %Y %H:%M:%S %Z", tmp);
	}
	if (path)
		pos+=snprintf(data+pos, sizeof(data)-pos, "; path=%s", path);
	if (domain)
		pos+=snprintf(data+pos, sizeof(data)-pos, "; domain=%s", domain);
	if (flags&OC_HTTP_ONLY)
		pos+=snprintf(data+pos, sizeof(data)-pos, "; HttpOnly");
	if (flags&OC_SECURE)
		pos+=snprintf(data+pos, sizeof(data)-pos, "; Secure");

	onion_response_set_header(res, "Set-Cookie",data);
	syslog(LOG_DEBUG, "Set cookie %s", data);
}
