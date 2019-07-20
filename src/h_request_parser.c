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
#include <nportredird.h>
#include <assert.h>
#include <protocol_type.h>
#include <protocol_http_type.h>
#include <dictionary.h>
#include <request.h>
#include <http_request_handler.h>
#include <codecs.h>
#include <vector.h>
#include <ptr_list.h>
#include <sessions_delegator_type.h>

//AA+
//extern ufsrv *const masterptr;
extern const Protocol *const protocols_registry_ptr;
//HTTP_PROTOCOL_MAXPOSTSIZE(protocols_registry_ptr);

/**
 * @short Known token types. This is merged with onion_connection_status as return value at token readers.
 * @private
 */
typedef enum{
	STRING=1001, // I start on 1000, to prevent collission with error codes
	KEY=1002,
	LINE=1003,
	NEW_LINE=1004,
	URLENCODE=1005,
	MULTIPART_BOUNDARY=1006,
	MULTIPART_END=1007,
	MULTIPART_NEXT=1008,
	STRING_NEW_LINE=1009,
}onion_token_token;

/// @private
typedef struct onion_token_s{
	char str[256*4*8];
	off_t pos;

	char *extra; // Only used when need some previous data, like at header value, i need the key
	size_t extra_size;
}onion_token;

/// @private
typedef struct onion_buffer_s{
	const char *data;
	size_t size;
	off_t pos;
}onion_buffer;

/**
 * @short This struct is mapped at token->extra. The token, _start and data are maped to token->extra area too.
 * @private
 *
 * This is a bit juggling with pointers, but needed to keep the deallocation simple, and the token object minimal in most cases.
 *
 * token->pos is the pointer to the free area and token->extra_size is the real size.
 */
typedef struct onion_multipart_buffer_s{
	char *boundary; /// Pointer to where the boundary is stored
	size_t size; 		/// Size of the boundary
	off_t pos;			/// Pos at the boundarycheck
	off_t startpos; /// Where did the boundary started (\n\r vs \n)
	char *data;			/// When need a new buffered data (always from stream), get it from here. This advances as used.
	char *name; 		/// point to a in data position
	char *filename; /// point to a in data position
	size_t file_total_size;	/// Total size of all file read data
	size_t post_total_size;	/// Total size of post, to check limits
	int fd; 				/// If file, the file descriptor.
}onion_multipart_buffer;

static void onion_request_parse_query_to_dict(onion_dict *dict, char *p);
static int onion_request_parse_query(onion_request *req);
static onion_connection_status prepare_POST(onion_request *req);
static onion_connection_status prepare_CONTENT_LENGTH(onion_request *req);
static onion_connection_status prepare_PUT(onion_request *req);


/// Reads a string until a non-string char. Returns an onion_token
int token_read_STRING(onion_token *token, onion_buffer *data){
	if (data->pos>=data->size)
		return OCS_NEED_MORE_DATA;

	char c=data->data[data->pos++];
	while (!is_space(c)){
		token->str[token->pos++]=c;
		if (data->pos>=data->size)
			return OCS_NEED_MORE_DATA;
		if (token->pos>=(sizeof(token->str)-1)){
			char tmp[16];
			strncpy(tmp, token->str, 16);
			tmp[15]='\0';
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Token too long to parse it. Part read start as %s (%ld bytes)",__func__, pthread_self(), tmp,token->pos);
			return OCS_INTERNAL_ERROR;
		}
		c=data->data[data->pos++];
	}
	int ret;
	if (c=='\n')
		ret=STRING_NEW_LINE;
	else
		ret=STRING;

	token->str[token->pos]='\0';
	token->pos=0;
	//ONION_DEBUG0("Found STRING token %s",token->str);
	return ret;
}

/**
 * @short Reads a string until a delimiter is found. Returns an onion_token. Also detects an empty line.
 *
 * @returns error code | STRING | STRING_NEW_LINE | NEW_LINE
 *
 * STRING is a delimited string, string new line is that the string finished witha  new line, new line is that I fuond only a new line char.
 */
///
int token_read_until(onion_token *token, onion_buffer *data, char delimiter){
	if (data->pos>=data->size)
		return OCS_NEED_MORE_DATA;

	//ONION_DEBUG0("Read data %d bytes, at token pos %d",data->size-data->pos, token->pos);

	char c=data->data[data->pos++];
	while (c!=delimiter && c!='\n'){
		if (c!='\r') // Just ignore it here
			token->str[token->pos++]=c;
		if (data->pos>=data->size){
			return OCS_NEED_MORE_DATA;
		}
		if (token->pos>=(sizeof(token->str)-1)){
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Token too long to parse it. Part read is %s (%ld bytes)",__func__, pthread_self(), token->str,token->pos);
			return OCS_INTERNAL_ERROR;
		}
		c=data->data[data->pos++];
	}
	int ret=STRING;
	token->str[token->pos]='\0';
	if (c!=delimiter){
		if ( token->pos==0 && c=='\n' ){
			ret=NEW_LINE;
		}
		else{ // only option left.
			ret=STRING_NEW_LINE;
		}
	}
	token->pos=0;

	//ONION_DEBUG0("Found KEY token %s",token->str);
	return ret;
}

/// Reads a key, that is a string ended with ':'.
int token_read_KEY(onion_token *token, onion_buffer *data){
	int res=token_read_until(token, data, ':');
	if (res==STRING)
		return KEY;
	if (res==STRING_NEW_LINE){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: When parsing header, found a non valid delimited string token: '%s'",__func__, pthread_self(), token->str);
		return OCS_INTERNAL_ERROR;
	}
	return res;
}

/// Reads a string until a '\n|\r\n' is found. Returns an onion_token.
int token_read_LINE(onion_token *token, onion_buffer *data){
	if (data->pos>=data->size)
		return OCS_NEED_MORE_DATA;

	char c=data->data[data->pos++];
	int ignore_to_end=0;
	while (c!='\n'){
		if (!ignore_to_end && (token->pos>=(sizeof(token->str)-1))){
			syslog(LOG_DEBUG, "Token too long to parse it. Ignoring remaining. ");
#ifdef __UF_FULLDEBUG
				char tmp[16];
				strncpy(tmp, token->str, 16);
				tmp[15]='\0';
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: Long token starts with: %s...",__func__, thread_self(), tmp);
#endif
			ignore_to_end=1;
		}
		if (!ignore_to_end)
			token->str[token->pos++]=c;
		if (data->pos>=data->size)
			return OCS_NEED_MORE_DATA;

		c=data->data[data->pos++];
	}
	if (token->str[token->pos-1]=='\r')
		token->str[token->pos-1]='\0';
	else
		token->str[token->pos]='\0';
	//token->pos=0;

	//ONION_DEBUG0("Found LINE token %s",token->str);
	return LINE;
}

/// Reads a string until a '\n|\r\n' is found. Returns an onion_token.
int token_read_URLENCODE(onion_token *token, onion_buffer *data){
	int l=data->size-data->pos;
	if (l > (token->extra_size-token->pos))
		l=token->extra_size-token->pos;
	//ONION_DEBUG0("Feed %d bytes",l);

	memcpy(&token->extra[token->pos], &data->data[data->pos], l);
	token->pos+=l;
	data->size-=l;

	if (token->extra_size==token->pos){
		token->extra[token->pos]='\0';
		return URLENCODE;
	}
	return OCS_NEED_MORE_DATA;
}

/// Reads as much as possible from the boundary.
int token_read_MULTIPART_BOUNDARY(onion_token *token, onion_buffer *data){
	onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	while (multipart->boundary[multipart->pos] && multipart->boundary[multipart->pos]==data->data[data->pos]){
		multipart->pos++;
		data->pos++;
		if (data->pos>=data->size)
			return OCS_NEED_MORE_DATA;
	}
	if (multipart->boundary[multipart->pos]){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: Expecting multipart boundary, but not here (pos %ld) (%c!=%c)", __func__, pthread_self(), multipart->pos, data->data[data->pos], multipart->boundary[multipart->pos]);
		return OCS_INTERNAL_ERROR;
	}
	return MULTIPART_BOUNDARY;
}

/// Reads as much as possible from the boundary.
int token_read_MULTIPART_next(onion_token *token, onion_buffer *data){
	//onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	while (token->pos<2 && (data->size-data->pos)>0){
		token->str[token->pos++]=data->data[data->pos++];
		if (token->pos==1 && token->str[0]=='\n'){
			token->pos=0;
			return MULTIPART_NEXT;
		}
	}
	//ONION_DEBUG("pos %d, %d %d (%c %c)",token->pos, token->str[0], token->str[1], token->str[0], token->str[1]);
	if (token->pos==2){
		token->pos=0;
		if (token->str[0]=='-' && token->str[1]=='-')
			return MULTIPART_END;
		if (token->str[0]=='\r' && token->str[1]=='\n')
			return MULTIPART_NEXT;
		return OCS_INTERNAL_ERROR;
	}

	return OCS_NEED_MORE_DATA;
}

int token_read_NEW_LINE(onion_token *token, onion_buffer *data){
	while (token->pos<2 && (data->size-data->pos)>0){
		token->str[token->pos++]=data->data[data->pos++];
		if (token->pos==1 && token->str[0]=='\n'){
			token->pos=0;
			return NEW_LINE;
		}
	}
	//ONION_DEBUG("pos %d, %d %d (%c %c)",token->pos, token->str[0], token->str[1], token->str[0], token->str[1]);
	int res=OCS_NEED_MORE_DATA;
	if (token->pos==2){
		token->pos=0;
		if (token->str[0]=='\r' && token->str[1]=='\n')
			res=NEW_LINE;
		else
			res=OCS_INTERNAL_ERROR;
	}
	token->pos=0;

	return res;
}

static char token_peek_next_char(onion_buffer *data){
	if (data->pos>=data->size)
		return '\0'; // If not enought data, go to safe side.
	return data->data[data->pos];
}

static onion_connection_status parse_POST_multipart_next(onion_request *req, onion_buffer *data);

/**
 * @short Reads from the data to fulfill content-length data.
 */
static onion_connection_status parse_CONTENT_LENGTH(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	size_t skip=data->pos; // First packet will be headers + some data, later ony data
	int length=data->size-skip;
	bool exit=false;
	size_t current_size=onion_block_size(req->data);

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: Adding data to request->data (non form POST) %lu + %d / %lu [%lu/%lu] %p", __func__, pthread_self(), current_size, length, token->extra_size, skip, data->size, data->data+current_size);
#endif

	if (length + current_size >= token->extra_size){
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "Done");
#endif
		exit=true;
		length=token->extra_size - current_size;
	}

	onion_block_add_data(req->data, &data->data[skip], length);
	data->pos+=length; // done

	if (exit)
		return OCS_REQUEST_READY;

	return OCS_NEED_MORE_DATA;
}

/**
 * @short Reads from the data to fulfill content-length data.
 *
 * All data is writen a temporal file, which will be removed later.
 */
static onion_connection_status parse_PUT(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int length=data->size-data->pos;
	int exit=0;

	if (length>=token->extra_size-token->pos){
		exit=1;
		length=token->extra_size-token->pos;
	}

	//ONION_DEBUG0("Writing %d. %d / %d bytes", length, token->pos+length, token->extra_size);

	int *fd=(int*)token->extra;
	ssize_t w=write(*fd, &data->data[data->pos], length);
	if (w<0){
        // cleanup
		close (*fd);
		free(token->extra);
		token->extra=NULL;
		syslog(LOG_DEBUG, "Could not write all data to temporal file.");
		return OCS_INTERNAL_ERROR;
	}
	data->pos+=length;
	token->pos+=length;

#if __DEBUG__
	const char *filename=onion_block_data(req->data);
	ONION_DEBUG0("Done with PUT. Created %s (%d bytes)", filename, token->pos);
#endif

	if (exit){
		close (*fd);
		free(token->extra);
		token->extra=NULL;
		return OCS_REQUEST_READY;
	}

	return OCS_NEED_MORE_DATA;
}

//AA+
size_t
HTTPProtoGetCurrentFileSize(onion_request *req)
{
	int flags=onion_request_get_flags(req);
	if ((flags&OR_METHODS)==OR_PUT) {
		onion_token *token=req->parser_data;
		return token->extra_size;
	} else if ((flags&OR_METHODS)==OR_POST) {
		onion_token *token=req->parser_data;
		if (token && token->extra) {
			onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
			if (multipart)	return multipart->file_total_size;
		}
	}

	return 0;
}

/**
 * Hard parser as I must set into the file as I read, until i found the boundary token (or start), try to parse, and if fail,
 * write to the file.
 *
 * The boundary may be in two or N parts.
 */
static onion_connection_status parse_POST_multipart_file(onion_request *req, onion_buffer *data){
	char tmp[1024]; /// Read 1024 bytes fo the read on this call, and write. If read less write as read.
	int tmppos=0;
	onion_token *token=req->parser_data;
	onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	const char *p=data->data+data->pos;
	for (;data->pos<data->size;data->pos++){
		//syslog(LOG_DEBUG, "*p %d boundary %d (%s)",*p,multipart->boundary[multipart->pos],multipart->boundary);
		if (multipart->pos==0){
			if (*p=='\n') // \r is optional.
				multipart->startpos=multipart->pos=1;
			else
				multipart->startpos=0;
		}
		if (*p==multipart->boundary[multipart->pos]){
			multipart->pos++;
			if (multipart->pos==multipart->size){
				multipart->startpos=multipart->pos=0;
				data->pos++; // Not sure why this is needed. FIXME.

				int w=write(multipart->fd,tmp,tmppos);
				if (w!=tmppos){
					syslog(LOG_DEBUG, "%s {pid:'%lu'}: Error writing multipart data to file. Check permissions on temp directory, and available disk.", __func__, pthread_self());
					close(multipart->fd);
					return OCS_INTERNAL_ERROR;
				}

				close(multipart->fd);
				req->parser=parse_POST_multipart_next;
				return OCS_NEED_MORE_DATA;
			}
		}
		else{
			if (multipart->file_total_size>PROTOHTTP_MAXFILESIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr)))
			{
			//if (multipart->file_total_size>masterptr->http.max_file_size){
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: Files on this post too big. Aborting.", __func__, pthread_self());
				return OCS_INTERNAL_ERROR;
			}
			if (multipart->pos!=0){
				multipart->file_total_size+=multipart->pos;
				int r=multipart->pos-multipart->startpos;
				//ONION_DEBUG0("Write %d bytes",r);
				int w=write(multipart->fd,tmp,tmppos);
				if (w!=tmppos){
					syslog(LOG_DEBUG, "%s {pid:'%lu'}: Error writing multipart data to file. Check permissions on temp directory, and availabe disk.", __func__, pthread_self());
					close(multipart->fd);
					return OCS_INTERNAL_ERROR;
				}
				tmppos=0;

				w=write(multipart->fd, multipart->boundary+multipart->startpos, r);
				if (w!=r){
					syslog(LOG_DEBUG, "%s {pid:'%lu'}: Error writing multipart data to file. Check permissions on temp directory, and availabe disk.", __func__, pthread_self());
					close(multipart->fd);
					return OCS_INTERNAL_ERROR;
				}
				multipart->startpos=multipart->pos=0;
				data->pos--; // Ignore read charater, try again. May be start of boundary.
				continue;
			}
			//ONION_DEBUG0("Write 1 byte");
			tmp[tmppos++]=*p;
			if (tmppos==sizeof(tmp)){
				int w=write(multipart->fd,tmp,tmppos);
				if (w!=tmppos){
					syslog(LOG_DEBUG, "%s {pid:'%lu'}: Error writing multipart data to file. Check permissions on temp directory, and availabe disk.", __func__, pthread_self());
					close(multipart->fd);
					return OCS_INTERNAL_ERROR;
				}
				tmppos=0;
			}
		}
		multipart->file_total_size++;
		p++;
	}
	int w=write(multipart->fd,tmp,tmppos);
	if (w!=tmppos){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Error writing multipart data to file. Check permissions on temp directory, and availabe disk.", __func__, pthread_self());
		close(multipart->fd);
		return OCS_INTERNAL_ERROR;
	}
	return OCS_NEED_MORE_DATA;
}

/**
 * Hard parser as I must set into the file as I read, until i found the boundary token (or start), try to parse, and if fail,
 * write to the file.
 *
 * The boundary may be in two or N parts.
 */
static onion_connection_status parse_POST_multipart_data(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	const char *p=data->data+data->pos;
	char *d=&multipart->data[token->pos];

	for (;data->pos<data->size;data->pos++){
		if (multipart->pos==0 && *p=='\n') // \r is optional.
			multipart->pos=1;
		if (*p==multipart->boundary[multipart->pos]){ // Check boundary
			multipart->pos++;
			if (multipart->pos==multipart->size){
				multipart->pos=0;
				data->pos++; // Not sure why this is needed. FIXME.
				if (token->pos>0 && *(d-1)=='\n'){
					token->pos--;
					d--;
				}
				if (token->pos>0 && *(d-1)=='\r')
					d--;

				*d='\0';
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: Adding POST data '%s'",  __func__, pthread_self(), multipart->name);
				onion_dict_add(req->POST, multipart->name, multipart->data, 0);
				multipart->data=multipart->data+token->pos+1;
				token->pos=0;
				req->parser=parse_POST_multipart_next;
				return OCS_NEED_MORE_DATA;
			}
		}
		else{ // No boundary
			if (multipart->pos!=0){// Maybe i was checking before... so I need to copy as much as I wrongly thought I got.
				if (multipart->post_total_size<=multipart->pos){
					syslog(LOG_DEBUG, "%s {pid:'%lu'}: No space left for this post." , __func__, pthread_self());
					return OCS_INTERNAL_ERROR;
				}
				multipart->post_total_size-=multipart->pos;
				memcpy(d,p,multipart->pos);
				d+=multipart->pos;
				token->pos+=multipart->pos;
				multipart->pos=0;
			}
			if (multipart->post_total_size<=0){
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: No space left for this post.", __func__, pthread_self());
				return OCS_INTERNAL_ERROR;
			}
			multipart->post_total_size--;
			//syslog(LOG_DEBUG, "%s (pid:'%lu'): post_total_size: '%d' %d", __func__, pthread_self(), multipart->post_total_size, token->extra_size - (int) (d-token->extra));
			*d=*p;
			d++;
			token->pos++;
		}
		p++;
	}
	return OCS_NEED_MORE_DATA;
}

static onion_connection_status parse_POST_multipart_headers_key(onion_request *req, onion_buffer *data);

static onion_connection_status parse_POST_multipart_content_type(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_until(token, data,';');

	if (res<=1000)
		return res;

	syslog(LOG_DEBUG, "Got content type %s",token->str);

	onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	const char *name;
	name=strstr(token->str, "filename=");
	if (name){
		int l=strlen(token->str)-9;
		if (l>multipart->post_total_size){
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Post buffer exhausted. content-Length wrong passed.",  __func__, pthread_self());
			return OCS_INTERNAL_ERROR;
		}
		multipart->filename=multipart->data;
		memcpy(multipart->filename, name+9, l);
		multipart->filename[l]=0;
		multipart->data=multipart->data+l+1;
		if (*multipart->filename=='"' && multipart->filename[l-2]=='"'){
			multipart->filename[l-2]='\0';
			multipart->filename++;
		}
		syslog(LOG_DEBUG, "Set filename '%s'",multipart->filename);
	}
	else{
		name=strstr(token->str, "name=");
		if (name){
			int l=strlen(token->str)-5;
			if (l>multipart->post_total_size){
				syslog(LOG_DEBUG, "%s {pid:'%lu}: Post buffer exhausted. Content-Length had wrong size.",  __func__, pthread_self());
				return OCS_INTERNAL_ERROR;
			}
			multipart->name=multipart->data;
			memcpy(multipart->name, name+5, l);
			multipart->name[l]=0;
			if (*multipart->name=='"' && multipart->name[l-2]=='"'){
				l-=2;
				multipart->name[l]='\0';
				multipart->name++;
			}
			multipart->data=multipart->name+l+1;

#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Set field name '%s'", __func__, pthread_self(), multipart->name);
#endif
		}
	}


	if (res==STRING_NEW_LINE){
		req->parser=parse_POST_multipart_headers_key;
		return OCS_NEED_MORE_DATA;
	}
	return OCS_NEED_MORE_DATA;
}

static onion_connection_status parse_POST_multipart_ignore_header(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_LINE(token, data);

	if (res<=1000)
		return res;
	token->pos=0;

	req->parser=parse_POST_multipart_headers_key;
	return OCS_NEED_MORE_DATA;
}

static onion_connection_status parse_POST_multipart_headers_key(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_KEY(token, data);

	if (res<=1000)
		return res;

	if (res==NEW_LINE){
		if (!req->POST)
			req->POST=onion_dict_new();
		//ONION_DEBUG("New line");
		onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
		multipart->pos=0;

		if (multipart->filename){
			char filename[]="/tmp/onion-XXXXXX";
			multipart->fd=mkstemp(filename);
			if (multipart->fd<0)
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: Could not create temporal file at %s.", __func__, pthread_self(), filename);//multipart->name, filename);
			if (!req->FILES)
				req->FILES=onion_dict_new();
			onion_dict_add(req->POST,multipart->name,multipart->filename, 0);
			onion_dict_add(req->FILES,multipart->name, filename, OD_DUP_VALUE);
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Created temporal file %s",__func__, pthread_self(), multipart->name, filename);
#endif
			req->parser=parse_POST_multipart_file;
			return parse_POST_multipart_file(req, data);
		}
		else{
			req->parser=parse_POST_multipart_data;
			return parse_POST_multipart_data(req, data);
		}
	}

	// Only interested in one header
	if (strcmp(token->str,"Content-Disposition")==0){
		req->parser=parse_POST_multipart_content_type;
		return parse_POST_multipart_content_type(req,data);
	}

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: Not interested in header '%s'", __func__, pthread_self(), token->str);
#endif

	req->parser=parse_POST_multipart_ignore_header;
	return parse_POST_multipart_ignore_header(req,data);
}

static onion_connection_status parse_POST_multipart_next(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_MULTIPART_next(token, data);

	if (res<=1000)
		return res;

	//ONION_DEBUG("Found next token: %d",res);

	if (res==MULTIPART_END)
		return OCS_REQUEST_READY;

	onion_multipart_buffer *multipart=(onion_multipart_buffer*)token->extra;
	multipart->filename=NULL;
	multipart->name=NULL;

	req->parser=parse_POST_multipart_headers_key;
	return parse_POST_multipart_headers_key(req, data);
}

static onion_connection_status parse_POST_multipart_start(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_MULTIPART_BOUNDARY(token, data);

	if (res<=1000)
		return res;

	req->parser=parse_POST_multipart_next;
	return parse_POST_multipart_next(req, data);
}

static onion_connection_status parse_POST_urlencode(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_URLENCODE(token, data);

	if (res<=1000)
		return res;

	req->POST=onion_dict_new();
	onion_request_parse_query_to_dict(req->POST, token->extra);
	token->extra=NULL; // At query to dict, it keeps the pointer and free it when POST is freed.

	return OCS_REQUEST_READY;
}

static onion_connection_status parse_headers_KEY(onion_request *req, onion_buffer *data);
static onion_connection_status parse_headers_VALUE(onion_request *req, onion_buffer *data);

static onion_connection_status parse_headers_VALUE_skip_leading_whitespace(onion_request *req, onion_buffer *data){
	while (data->pos<data->size){
		char peek=data->data[data->pos++];
		if (peek!='\t' && peek!=' '){
			onion_token *token=req->parser_data;
			if (peek=='\n')
				return OCS_NEED_MORE_DATA;
			token->str[token->pos++]=' ';
			token->str[token->pos++]=peek;
			req->parser=parse_headers_VALUE;
			return parse_headers_VALUE(req, data);
		}
	}
	return OCS_NEED_MORE_DATA;
}

static onion_connection_status parse_headers_VALUE_multiline_if_space(onion_request *req, onion_buffer *data){
	char peek=token_peek_next_char(data);
	//syslog(LOG_DEBUG, "Multiline if space, peek %d",peek);
	if (peek==0){
		req->parser=parse_headers_VALUE_multiline_if_space;
		return OCS_NEED_MORE_DATA;
	}
	if (peek==' ' || peek=='\t'){
		req->parser=parse_headers_VALUE_skip_leading_whitespace;
		return parse_headers_VALUE_skip_leading_whitespace(req, data);
	}
	onion_token *token=req->parser_data;
	token->pos=0;

	char *p=token->str; // skips leading spaces
	while (is_space(*p)) p++;

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: Adding header %s : %s", __func__, pthread_self(), token->extra,p);
#endif

	onion_dict_add(req->headers,token->extra,p, OD_DUP_VALUE|OD_FREE_KEY);
	token->extra=NULL; // It will be freed at onion_dict_free.

	req->parser=parse_headers_KEY;
	return OCS_NEED_MORE_DATA; // Get back recursion if any, to prevent too long callstack (on long headers) and stack overflow.
}

static onion_connection_status parse_headers_VALUE(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_LINE(token, data);

	if (res<=1000)
		return res;

	return parse_headers_VALUE_multiline_if_space(req, data);
}

static onion_connection_status parse_headers_KEY(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;

	int res=token_read_KEY(token, data);

	if (res<=1000)
		return res;

  //syslog(LOG_DEBUG, "%s: Got %d at KEY", __func__, res);

	if ( res == NEW_LINE ){
		if ((req->flags&OR_METHODS)==OR_POST){
			const char *content_type=onion_request_get_header(req, "Content-Type");
			if (content_type && (strstr(content_type,"application/x-www-form-urlencoded") || strstr(content_type, "boundary")))
				return prepare_POST(req);
		}
		if ((req->flags&OR_METHODS)==OR_PUT)
			return prepare_PUT(req);
		if (onion_request_get_header(req, "Content-Length")){ // Some length, not POST, get data.
			int n=atoi(onion_request_get_header(req, "Content-Length"));
			if (n>0)
				return prepare_CONTENT_LENGTH(req);
		}

		return OCS_REQUEST_READY;
	}
	assert(token->extra==NULL);
	token->extra=strdup(token->str);

	req->parser=parse_headers_VALUE;
	return parse_headers_VALUE(req, data);
}

static onion_connection_status parse_headers_KEY_skip_NL(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int r=token_read_NEW_LINE(token,data);

	if (r<=1000)
		return r;

	req->parser=parse_headers_KEY;
	return parse_headers_KEY(req, data);
}

static onion_connection_status parse_headers_VERSION(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_STRING(token, data);

	if (res<=1000)
		return res;

	if (strcmp(token->str,"HTTP/1.1")==0)
		req->flags|=OR_HTTP11;

	if (!req->GET)
		req->GET=onion_dict_new();

	if (res==STRING){
		req->parser=parse_headers_KEY_skip_NL;
		return parse_headers_KEY_skip_NL(req, data);
	}
	else{ // STRING_NEW_LINE, only when \n as STRING separator, not \r\n.
		req->parser=parse_headers_KEY;
		return parse_headers_KEY(req, data);
	}
}

static onion_connection_status parse_headers_URL(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_STRING(token, data);

	if (res<=1000)
		return res;

	req->fullpath=mystrdup(token->str);
	onion_request_parse_query(req);

	syslog(LOG_DEBUG, "%s {pid:'%lu'}: URL path is %s", __func__, pthread_self(), req->fullpath);

  if (res==STRING_NEW_LINE){ // Old HTTP/0? or lazy user, dont set the HTTP version, straigth new line.
    req->parser=parse_headers_KEY;
    return parse_headers_KEY(req, data);
  }
  else{
    req->parser=parse_headers_VERSION;
    return parse_headers_VERSION(req, data);
  }
}

static onion_connection_status parse_headers_GET(onion_request *req, onion_buffer *data){
	onion_token *token=req->parser_data;
	int res=token_read_STRING(token, data);

	if (res<=1000)
		return res;

	int i;
	for (i=0;i<16;i++) {
		if (!onion_request_methods[i]) {
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Unknown method '%s' (%d known methods)", __func__, pthread_self(), token->str, i);
			return OCS_NOT_IMPLEMENTED;
		}

		if (strcmp(onion_request_methods[i], token->str)==0){
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Method is %s", __func__, pthread_self(), token->str);
#endif
			req->flags=(req->flags&~0x0F)+i;
			break;
		}
	}
	req->parser=parse_headers_URL;

	return parse_headers_URL(req, data);
}

/**
 * @short Write some data into the request, and passes it line by line to onion_request_fill
 *
 * It features a state machine, from req->parse_state.
 *
 * Depending on the state input is redirected to a different parser, one for headers, POST url encoded data...
 *
 * @return Returns the number of bytes writen, or <=0 if connection should close, according to onion_connection_status
 * @see onion_connection_status
 */
onion_connection_status onion_request_write(Session *sesn_ptr, onion_request *req, const char *data, size_t size)
{
	if (size == 0) {
		if (data == NULL) {
			syslog (LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_PROTO_INCONSISTENT_STATE, "INPUT BUFFER/SIZE EMPTY");
		} else {
			syslog (LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_PROTO_INCONSISTENT_STATE, "INPUT BUFFER ZERO BUT BUFFER IS NOT NULL");
		}

		return OCS_NEED_MORE_DATA;
	}

	if (!req->parser_data) {
		req->parser_data  = calloc(1, sizeof(onion_token));
		req->parser       = parse_headers_GET;
	}

	onion_connection_status (*parse)(onion_request *req, onion_buffer *data);
	parse = req->parser;

	if (parse) {
		onion_buffer odata = { data, size, 0};
		while (odata.size>odata.pos) {
			int r=parse(req, &odata);
			if (r!=OCS_NEED_MORE_DATA) {
				return r;
			}

			parse = req->parser;
		}

		return OCS_NEED_MORE_DATA;
	}

	return OCS_INTERNAL_ERROR;
}

/**
 * @short Parses the query to unquote the path and get the query.
 */
static int onion_request_parse_query(onion_request *req){
	if (!req->fullpath)
		return 0;
	if (req->GET) // already done
		return 1;

	char *p=req->fullpath;
	char have_query=0;
	while(*p){
		if (*p=='?'){
			have_query=1;
			break;
		}
		p++;
	}
	*p='\0';
	onion_unquote_inplace(req->fullpath);
	if (have_query){ // There are querys.
		p++;
		req->GET=onion_dict_new();
		onion_request_parse_query_to_dict(req->GET, p);
	}
	return 1;
}

/**
 * @short Parses the query part to a given dictionary.
 *
 * The data is overwriten as necessary. It is NOT dupped, so if you free this char *p, please free the tree too.
 */
static void onion_request_parse_query_to_dict(onion_dict *dict, char *p){
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: Query to dict %s",__func__, pthread_self(), p);
	char *key=NULL, *value=NULL;
	int state=0;  // 0 key, 1 value
	key=p;
	while(*p){
		if (state==0){
			if (*p=='='){
				*p='\0';
				value=p+1;
				state=1;
			}
			else if (*p=='&'){
				*p='\0';
				onion_unquote_inplace(key);
				//syslog(LOG_DEBUG, "Adding key %s",key);
				onion_dict_add(dict, key, "", 0);
				key=p+1;
				state=0;
			}
		}
		else{
			if (*p=='&'){
				*p='\0';
				onion_unquote_inplace(key);
				onion_unquote_inplace(value);
				//syslog(LOG_DEBUG, "Adding key %s=%-16s",key,value);
				onion_dict_add(dict, key, value, 0);
				key=p+1;
				state=0;
			}
		}
		p++;
	}
	if (state==0){
		if (key[0]!='\0'){
			onion_unquote_inplace(key);
			//syslog(LOG_DEBUG, "Adding key %s",key);
			onion_dict_add(dict, key, "", 0);
		}
	}
	else{
		onion_unquote_inplace(key);
		onion_unquote_inplace(value);
		//syslog(LOG_DEBUG, "Adding key %s=%-16s",key,value);
		onion_dict_add(dict, key, value, 0);
	}
}

/**
 * @short Prepares the POST
 */
static onion_connection_status prepare_POST(onion_request *req){
	// ok post
	onion_token *token=req->parser_data;
	const char *content_type=onion_dict_get(req->headers, "Content-Type");
	const char *content_size=onion_dict_get(req->headers, "Content-Length");

	if (!content_size)
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: I need the content size header to support POST data", __func__, pthread_self());
		return OCS_INTERNAL_ERROR;
	}
	size_t cl=atol(content_size);
	if (cl==0)
		return OCS_REQUEST_READY;

	//ONION_DEBUG("Content type %s",content_type);
	if (!content_type || (strstr(content_type, "application/x-www-form-urlencoded"))){
		if (cl>PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr))){
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: Asked to send much POST data. Limit %lu. Failing.",__func__, pthread_self(), PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr)));
			return OCS_INTERNAL_ERROR;
		}

		//AA+ replace with the if-else block below
		//assert(token->extra==NULL);

		if (token->extra==NULL)
		{
			token->extra=malloc(cl+1); // Cl + \0
			token->extra_size=cl;
			req->free_list=onion_ptr_list_add(req->free_list, token->extra); // Free when the request is freed.

			req->parser=parse_POST_urlencode;
			return OCS_NEED_MORE_DATA;
		}
		else
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: INTERNAL STATE token->extra should have been NULL",__func__, pthread_self());
			return OCS_INTERNAL_ERROR;
		}
	}

	// multipart.

	const char *mp_token=strstr(content_type, "boundary=");
	if (!mp_token){
		syslog(LOG_DEBUG, "No boundary set at content-type");
		return OCS_INTERNAL_ERROR;
	}
	mp_token+=9;
	if (cl>PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr))) // I hope the missing part is files, else error later.
		cl=PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr));

	int mp_token_size=strlen(mp_token);
	token->extra_size=cl; // Max size of the multipart->data
	onion_multipart_buffer *multipart=malloc(token->extra_size+sizeof(onion_multipart_buffer)+mp_token_size+2);
	assert(token->extra==NULL);
	token->extra=(char*)multipart;

	multipart->boundary=(char*)multipart+sizeof(onion_multipart_buffer)+1;
	multipart->size=mp_token_size+4;
	multipart->pos=2; // First boundary already have [\r]\n readen
	multipart->post_total_size=cl;
	multipart->file_total_size=0;
	multipart->boundary[0]='\r';
	multipart->boundary[1]='\n';
	multipart->boundary[2]='-';
	multipart->boundary[3]='-';
	strcpy(&multipart->boundary[4],mp_token);
	multipart->data=(char*)multipart+sizeof(onion_multipart_buffer)+multipart->size+1;

	//ONION_DEBUG("Multipart POST boundary '%s'",multipart->boundary);

	req->parser=parse_POST_multipart_start;

	return OCS_NEED_MORE_DATA;
}

/**
 * @short Prepares the CONTENT LENGTH
 */
static onion_connection_status prepare_CONTENT_LENGTH(onion_request *req){
	onion_token *token=req->parser_data;
	const char *content_size=onion_dict_get(req->headers, "Content-Length");
	if (!content_size){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}:I need the Content-Length header to get data", __func__, pthread_self());
		return OCS_INTERNAL_ERROR;
	}
	size_t cl=atol(content_size);

	if (cl>PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr))){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Trying to set more data at server than allowed %lu", __func__, pthread_self(), PROTOHTTP_MAXPOSTSIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr)));
		return OCS_INTERNAL_ERROR;
	}

	req->data=onion_block_new();

	assert(token->extra==NULL);
	//token->extra=NULL; // Should be already null, as should have no data.
	token->extra_size=cl;
	token->pos=0;

	req->parser=parse_CONTENT_LENGTH;
	return OCS_NEED_MORE_DATA;
}

/**
 * @short Prepares the PUT
 *
 * It saves the data to a temporal file, which name is stored at data.
 */
static onion_connection_status prepare_PUT(onion_request *req){
	onion_token *token=req->parser_data;
	const char *content_size=onion_dict_get(req->headers, "Content-Length");
	if (!content_size){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: I need the Content-Length header to get data", __func__, pthread_self());
		return OCS_INTERNAL_ERROR;
	}
	size_t cl=atol(content_size);

	if (cl>PROTOHTTP_MAXFILESIZE(HTTP_PROTOCOL_DATA(protocols_registry_ptr))){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Trying to PUT a file bigger than allowed size", __func__, pthread_self());
		return OCS_INTERNAL_ERROR;
	}

	req->data=onion_block_new();

	char filename[]="/tmp/onion-XXXXXX";
	int fd=mkstemp(filename);
	if (fd<0)
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Could not create temporary file at %s.", __func__, pthread_self(), filename);

	onion_block_add_str(req->data, filename);

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: Creating PUT file %s (%lu bytes long)", __func__, pthread_self(), filename, token->extra_size);
#endif

	if (!req->FILES){
		req->FILES=onion_dict_new();
	}
	{
	const char *filename=onion_block_data(req->data);
	onion_dict_add(req->FILES,"filename", filename, 0);
	}


	if (cl==0){
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Created 0 length file",__func__, pthread_self());
		close(fd);
		return OCS_REQUEST_READY;
	}

	int *pfd=malloc(sizeof(fd));
	*pfd=fd;

	assert(token->extra==NULL);
	token->extra=(char*)pfd;
	token->extra_size=cl;
	token->pos=0;

	req->parser=parse_PUT;
	return OCS_NEED_MORE_DATA;
}

/**
 * @short Frees the parser data.
 */
void onion_request_parser_data_free(void *t){
	//syslog(LOG_DEBUG, "Free parser data");
	onion_token *token=t;
	if (token->extra){
		free(token->extra);
		token->extra=NULL;
	}
	free(token);
}
