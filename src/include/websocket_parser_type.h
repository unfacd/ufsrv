/*
 *
 *  Created on: 19 Mar 2015
 *      Author: ayman
 */

#ifndef INCLUDE_WEBSOCKET_PARSER_TYPE_H_
#define INCLUDE_WEBSOCKET_PARSER_TYPE_H_


#define FAIL_CHAR 0x08
#define LWS_MAX_HEADER_LEN 1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/*
 * these have to be kept in sync with lextable.h / minilex.c
 *
 * NOTE: These public enums are part of the abi.  If you want to add one,
 * add it at where specified so existing users are unaffected.
 */

#if 1
enum lws_token_indexes {
	WSI_TOKEN_GET_URI=0,
	WSI_TOKEN_POST_URI=1,
	WSI_TOKEN_OPTIONS_URI=2,

	WSI_TOKEN_HOST=3,
	WSI_TOKEN_CONNECTION=4,
	WSI_TOKEN_UPGRADE=5,
	WSI_TOKEN_ORIGIN=6,

	WSI_TOKEN_DRAFT=7,
	WSI_TOKEN_CHALLENGE=8,
	WSI_TOKEN_EXTENSIONS=9,
	WSI_TOKEN_KEY1=10,
	WSI_TOKEN_KEY2=11,
	WSI_TOKEN_PROTOCOL=12,

	WSI_TOKEN_ACCEPT=13,
	WSI_TOKEN_NONCE=14,

	WSI_TOKEN_HTTP=15,
	WSI_TOKEN_HTTP2_SETTINGS=16,
	WSI_TOKEN_HTTP_ACCEPT=17,
	WSI_TOKEN_HTTP_AC_REQUEST_HEADERS=18,

	WSI_TOKEN_HTTP_IF_MODIFIED_SINCE=19,
	WSI_TOKEN_HTTP_IF_NONE_MATCH=20,
	WSI_TOKEN_HTTP_ACCEPT_ENCODING=21,
	WSI_TOKEN_HTTP_ACCEPT_LANGUAGE=22,

	WSI_TOKEN_HTTP_PRAGMA=23,
	WSI_TOKEN_HTTP_COOKIE=24,
	WSI_TOKEN_HTTP_CONTENT_LENGTH=25,
	WSI_TOKEN_HTTP_CONTENT_TYPE=26,
	WSI_TOKEN_KEY=27,
	WSI_TOKEN_VERSION=28,
	WSI_TOKEN_SWORIGIN=29,
	WSI_TOKEN_HTTP_USER_AGENT=30,
	X_UFSRVCID=31,
	X_CM_TOKEN=32,
	X_FORWARDED_FOR=33,
	WSI_TOKEN_HTTP_URI_ARGS,

	// use token storage to stash these
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_PEER_ADDRESS,
	_WSI_TOKEN_CLIENT_URI,
	_WSI_TOKEN_CLIENT_HOST,
	_WSI_TOKEN_CLIENT_ORIGIN,

	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE,
	WSI_INIT_TOKEN_MUXURL,
};
#endif

enum uri_path_states {
	URIPS_IDLE,
	URIPS_SEEN_SLASH,
	URIPS_SEEN_SLASH_DOT,
	URIPS_SEEN_SLASH_DOT_DOT,
};
enum uri_esc_states {
	URIES_IDLE,
	URIES_SEEN_PERCENT,
	URIES_SEEN_PERCENT_H1,
};

struct lws_fragments {
	unsigned short offset;
	unsigned short len;
	unsigned char nfrag; /* which ah->frag[] continues this content, or 0 */
};

/*
 * these are assigned from a pool held in the context.
 * Both client and server mode uses them for http header analysis
 */
struct allocated_headers {
	char data[LWS_MAX_HEADER_LEN];
	/*
	 * the randomly ordered fragments, indexed by frag_index and
	 * lws_fragments->nfrag for continuation.
	 */
	struct lws_fragments frags[WSI_TOKEN_COUNT * 2];
	/*
	 * for each recognized token, frag_index says which frag[] his data
	 * starts in (0 means the token did not appear)
	 * the actual header data gets dumped as it comes in, into data[]
	 */
	unsigned char frag_index[WSI_TOKEN_COUNT];

	unsigned short pos;
	unsigned char in_use;
	unsigned char nfrag;
};


struct _lws_header_related {
	/* MUST be first in struct */
	struct allocated_headers *ah;

	enum uri_path_states ups;
	enum uri_esc_states ues;
	short lextable_pos;
	unsigned short current_token_limit;
	char esc_stash;
	char post_literal_equal;
	unsigned char parser_state; /* enum lws_token_indexes */
};

struct lws {
	union u {
		struct _lws_header_related hdr;
	} u;
	unsigned int hdr_parsing_completed:1;

	/* chars */
#ifndef LWS_NO_EXTENSIONS
	unsigned char count_act_ext;
#endif
	unsigned char ietf_spec_revision;
	char mode; /* enum connection_mode */
	char state; /* enum lws_connection_states */
};

typedef struct lws lws;

#endif /* INCLUDE_USERS_H_ */
