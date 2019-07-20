/*
 * http_request_handler.h
 *
 *  Created on: 27 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_HTTP_REQUEST_HANDLER_H_
#define SRC_INCLUDE_HTTP_REQUEST_HANDLER_H_

#include <vector_type.h>
#include <dictionary_type.h>
#include <session.h>

#define ONION_REQUEST_BUFFER_SIZE 256
#define ONION_RESPONSE_BUFFER_SIZE XXLBUF

// In the HTTP RFC whitespace is always these characters
// and is not locale independent, we'll need this when
// parsing
static int __attribute__ ((unused)) is_space(char c) {
	if(c == '\t' || c == '\n' || c == '\r' || c == ' ')
		return 1;
	return 0;
}
static int __attribute__ ((unused)) is_alnum(char c) {
	if((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
		return 1;
	return 0;
}

struct onion_ptr_list_t{
	void *ptr;
	struct onion_ptr_list_t *next;
};
typedef struct onion_ptr_list_t onion_ptr_list;

struct onion_request_t{
#if 1
	struct{
		//onion_listen_point *listen_point;
		void *user_data;
		//int fd; ///< Original fd, to use at polling.
		struct sockaddr_storage cli_addr;
		socklen_t cli_len;
		char *cli_info;
	}connection;  /// Connection to the client.
#endif
	int flags;            /// Flags for this response. Ored onion_request_flags_e

	char *fullpath;       /// Original path for the request
	char *path;           /// Path at this level. Its actually a pointer inside fullpath, removing the leading parts already processed by handlers
	onion_dict *headers;  /// Headers prepared for this response.
	onion_dict *GET;      /// When the query (?q=query) is processed, the dict with the values @see onion_request_parse_query
	onion_dict *POST;     /// Dictionary with POST values
	onion_dict *FILES;    /// Dictionary with files. They are automatically saved at /tmp/ and removed at request free. mapped string is full path.
	onion_dict *session;  /// Pointer to related session
	onion_block *data;    /// Some extra data from PUT, normally PROPFIND.
	onion_dict *cookies;  /// Data about cookies.
	char *session_id;     /// Session id of the request, if any.
	void *parser;         /// When recieving data, where to put it. Check at request_parser.c.
	void *parser_data;    /// Data necesary while parsing, muy be deleted when state changed. At free is simply freed.
	//onion_websocket *websocket; /// Websocket handler.
	onion_ptr_list *free_list; /// Memory that should be freed when the request finishes. IT allows to have simpler onion_dict, which dont copy/free data, but just splits a long string inplace.
};
typedef struct onion_request_t onion_request;

struct onion_response_t{
	onion_request *request;  	/// Original request, so both are related, and get connected to the onion_t structure. Writes through the request connection.
	onion_dict *headers;			/// Headers to write when appropiate.
	int code;									/// Response code
	int flags;								/// Flags. @see onion_response_flags_e
	unsigned int length;			/// Length, if known, of the response, to create the Content-Lenght header.
	unsigned int sent_bytes; 	/// Sent bytes at content.
	unsigned int sent_bytes_total; /// Total sent bytes, including headers.
	char buffer[XXLBUF/*ONION_RESPONSE_BUFFER_SIZE*/]; /// buffer of output data. This way its do not send small chunks all the time, but blocks, so better network use. Also helps to keep alive connections with less than block size bytes.
	off_t buffer_pos;						/// Position in the internal buffer. When sizeof(buffer) its flushed to the onion IO.
};
typedef struct onion_response_t onion_response;

/**
 * @short The desired connection state of the connection.
 * @ingroup handler
 *
 * If <0 it means close connection. May mean also to show something to the client.
 */
enum onion_connection_status_e{
	OCS_NOT_PROCESSED=0,
	OCS_NEED_MORE_DATA=1,
	OCS_PROCESSED=2,
	OCS_CLOSE_CONNECTION=-2,
	OCS_KEEP_ALIVE=3,
	OCS_WEBSOCKET=4,
  OCS_REQUEST_READY=5, ///< Internal. After parsing the request, it is ready to handle.
	OCS_INTERNAL_ERROR=-500,
	OCS_NOT_IMPLEMENTED=-501,
  OCS_FORBIDDEN=-502,
  OCS_YIELD=-3, ///< Do not remove the request/response from the pollers, I will manage it in another thread (for exmaple longpoll)
};

typedef enum onion_connection_status_e onion_connection_status;

/// Signature of request handlers.
/// @ingroup handler
typedef onion_connection_status (*onion_handler_handler)(Session *, void *privdata, onion_request *req, onion_response *res);
typedef void (*onion_handler_private_data_free)(void *privdata);

struct onion_handler_t{
	onion_handler_handler handler;  /// callback that should return an onion_connection_status, and maybe process the request.
	onion_handler_private_data_free priv_data_free;  /// When freeing some memory, how to remove the private memory.
	void *priv_data;                /// Private data as needed by the handler

	struct onion_handler_t *next; /// If parser returns null, i try next handler. If no next handler i go up, or return an error. @see onion_handler_handle
};
typedef struct onion_handler_t onion_handler;

/**
 * @struct onion_url_t
 * @short Url regexp pack. This is also a handler, and can be converted with onion_url_to_handle.
 * @ingroup url
 */
struct onion_url_t;
typedef struct onion_url_t onion_url; //fake type to obscure handler

#endif /* SRC_INCLUDE_HTTP_REQUEST_HANDLER_H_ */
