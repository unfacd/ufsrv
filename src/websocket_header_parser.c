#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <main.h>

#include <websocket_parser_type.h>

unsigned char lextable[] = {
	#include "lextable.h"
};

#if 0
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
#endif

inline static int lextable_decode(int pos, char c)
{
	if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';

		while (1) {
			if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
				if ((lextable[pos] & 0x7f) != c)
					return -1;
				/* fall thru */
				pos++;
				if (lextable[pos] == FAIL_CHAR)
					return -1;
				return pos;
			}

			if (lextable[pos] == FAIL_CHAR)
				return -1;

			/* b7 = 0, end or 3-byte */
			if (lextable[pos] < FAIL_CHAR) /* terminal marker */
				return pos;

			if (lextable[pos] == c) /* goto */
				return pos + (lextable[pos + 1]) +
							(lextable[pos + 2] << 8);
			/* fall thru goto */
			pos += 3;
			/* continue */
		}
}

inline static char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

inline static int lws_pos_in_bounds(struct lws *wsi)
{
	if (wsi->u.hdr.ah->pos < LWS_MAX_HEADER_LEN)//wsi->context->max_http_header_data) //AA-
		return 0;

	if (wsi->u.hdr.ah->pos == LWS_MAX_HEADER_LEN){//wsi->context->max_http_header_data) { //AA-
		//printf("Ran out of header data space\n");
		return 1;
	}

	/*
	 * with these tests everywhere, it should never be able to exceed
	 * the limit, only meet the limit
	 */

	//printf("%s: pos %d, limit %d\n", __func__, wsi->u.hdr.ah->pos,LWS_MAX_HEADER_LEN);
		 //wsi->context->max_http_header_data); //AA-
	//assert(0); //AA-

	return 1;
}


inline static int issue_char(struct lws *wsi, unsigned char c)
{
	unsigned short frag_len;

		if (lws_pos_in_bounds(wsi))
			return -1;

		frag_len = wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len;
		/*
		 * If we haven't hit the token limit, just copy the character into
		 * the header
		 */
		if (frag_len < wsi->u.hdr.current_token_limit) {
			wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
			if (c)
				wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len++;
			return 0;
		}

		/* Insert a null character when we *hit* the limit: */
		if (frag_len == wsi->u.hdr.current_token_limit) {
			if (lws_pos_in_bounds(wsi))
				return -1;
			wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = '\0';
			/*printf("header %i exceeds limit %d\n",
				  wsi->u.hdr.parser_state,
				  //wsi->u.hdr.current_token_limit);*/
		}

		return 1;
//AA-
#if 0
	if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
		//printf("excessive header content\n");
		return -1;
	}

	if( wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len >=
		wsi->u.hdr.current_token_limit) {
		//printf("header %i exceeds limit\n", wsi->u.hdr.parser_state);
		return 1;
	};

	wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
	if (c)
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;

	return 0;
#endif
}

inline static char *lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h)
{
	int n;

		n = wsi->u.hdr.ah->frag_index[h];
		if (!n)
			return NULL;

		return wsi->u.hdr.ah->data + wsi->u.hdr.ah->frags[n].offset;
}

//tick
inline static int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].nfrag;
	} while (n);

	return len;
}


int ws_parse(struct lws *wsi, unsigned char c)
{
	static const unsigned char methods[] = {
		WSI_TOKEN_GET_URI,
	};
	struct allocated_headers *ah = wsi->u.hdr.ah;
	//struct lws_context *context = wsi->context; //AA-
	unsigned int n, m, enc = 0;

	//AA-
	//assert(wsi->u.hdr.ah);

	switch (wsi->u.hdr.parser_state) {
	default:

		//printf("WSI_TOK_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional initial space swallow */
		if (!ah->frags[ah->frag_index[wsi->u.hdr.parser_state]].len &&
		    c == ' ')
			break;

		for (m = 0; m < ARRAY_SIZE(methods); m++)
			if (wsi->u.hdr.parser_state == methods[m])
				break;
		if (m == ARRAY_SIZE(methods))
			/* it was not any of the methods */
			goto check_eol;

		/* special URI processing... end at space */

		if (c == ' ') {
			/* enforce starting with / */
			if (!ah->frags[ah->nfrag].len)
				if (issue_char(wsi, '/') < 0)
					return -1;

			if (wsi->u.hdr.ups == URIPS_SEEN_SLASH_DOT_DOT) {
				/*
				 * back up one dir level if possible
				 * safe against header fragmentation because
				 * the method URI can only be in 1 fragment
				 */
				if (ah->frags[ah->nfrag].len > 2) {
					ah->pos--;
					ah->frags[ah->nfrag].len--;
					do {
						ah->pos--;
						ah->frags[ah->nfrag].len--;
					} while (ah->frags[ah->nfrag].len > 1 &&
						 ah->data[ah->pos] != '/');
				}
			}

			/* begin parsing HTTP version: */
			if (issue_char(wsi, '\0') < 0)
				return -1;
			wsi->u.hdr.parser_state = WSI_TOKEN_HTTP;
			goto start_fragment;
		}

		/*
		 * PRIORITY 1
		 * special URI processing... convert %xx
		 */

		switch (wsi->u.hdr.ues) {
		case URIES_IDLE:
			if (c == '%') {
				wsi->u.hdr.ues = URIES_SEEN_PERCENT;
				goto swallow;
			}
			break;
		case URIES_SEEN_PERCENT:
			if (char_to_hex(c) < 0)
				/* illegal post-% char */
				goto forbid;

			wsi->u.hdr.esc_stash = c;
			wsi->u.hdr.ues = URIES_SEEN_PERCENT_H1;
			goto swallow;

		case URIES_SEEN_PERCENT_H1:
			if (char_to_hex(c) < 0)
				/* illegal post-% char */
				goto forbid;

			c = (char_to_hex(wsi->u.hdr.esc_stash) << 4) |
					char_to_hex(c);
			enc = 1;
			wsi->u.hdr.ues = URIES_IDLE;
			break;
		}

		/*
		 * PRIORITY 2
		 * special URI processing...
		 *  convert /.. or /... or /../ etc to /
		 *  convert /./ to /
		 *  convert // or /// etc to /
		 *  leave /.dir or whatever alone
		 */

		switch (wsi->u.hdr.ups) {
		case URIPS_IDLE:
			if (!c)
				return -1;
			/* genuine delimiter */
			if ((c == '&' || c == ';') && !enc) {
				if (issue_char(wsi, c) < 0)
					return -1;
				/* swallow the terminator */
				ah->frags[ah->nfrag].len--;
				/* link to next fragment */
				ah->frags[ah->nfrag].nfrag = ah->nfrag + 1;
				ah->nfrag++;
				if (ah->nfrag >= ARRAY_SIZE(ah->frags))
					goto excessive;
				/* start next fragment after the & */
				wsi->u.hdr.post_literal_equal = 0;
				ah->frags[ah->nfrag].offset = ah->pos;
				ah->frags[ah->nfrag].len = 0;
				ah->frags[ah->nfrag].nfrag = 0;
				goto swallow;
			}
			/* uriencoded = in the name part, disallow */
			if (c == '=' && enc &&
			    ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] &&
			    !wsi->u.hdr.post_literal_equal)
				c = '_';

			/* after the real =, we don't care how many = */
			if (c == '=' && !enc)
				wsi->u.hdr.post_literal_equal = 1;

			/* + to space */
			if (c == '+' && !enc)
				c = ' ';
			/* issue the first / always */
			if (c == '/' && !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS])
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_SEEN_SLASH:
			/* swallow subsequent slashes */
			if (c == '/')
				goto swallow;
			/* track and swallow the first . after / */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT;
				goto swallow;
			}
			wsi->u.hdr.ups = URIPS_IDLE;
			break;
		case URIPS_SEEN_SLASH_DOT:
			/* swallow second . */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT_DOT;
				goto swallow;
			}
			/* change /./ to / */
			if (c == '/') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				goto swallow;
			}
			/* it was like /.dir ... regurgitate the . */
			wsi->u.hdr.ups = URIPS_IDLE;
			if (issue_char(wsi, '.') < 0)
				return -1;
			break;

		case URIPS_SEEN_SLASH_DOT_DOT:

			/* /../ or /..[End of URI] --> backup to last / */
			if (c == '/' || c == '?') {
				/*
				 * back up one dir level if possible
				 * safe against header fragmentation because
				 * the method URI can only be in 1 fragment
				 */
				if (ah->frags[ah->nfrag].len > 2) {
					ah->pos--;
					ah->frags[ah->nfrag].len--;
					do {
						ah->pos--;
						ah->frags[ah->nfrag].len--;
					} while (ah->frags[ah->nfrag].len > 1 &&
						 ah->data[ah->pos] != '/');
				}
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				if (ah->frags[ah->nfrag].len > 1)
					break;
				goto swallow;
			}

			/*  /..[^/] ... regurgitate and allow */

			if (issue_char(wsi, '.') < 0)
				return -1;
			if (issue_char(wsi, '.') < 0)
				return -1;
			wsi->u.hdr.ups = URIPS_IDLE;
			break;
		}

		if (c == '?' && !enc &&
		    !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS]) { /* start of URI arguments */
			if (wsi->u.hdr.ues != URIES_IDLE)
				goto forbid;

			/* seal off uri header */
			if (issue_char(wsi, '\0') < 0)
				return -1;

			/* move to using WSI_TOKEN_HTTP_URI_ARGS */
			ah->nfrag++;
			if (ah->nfrag >= ARRAY_SIZE(ah->frags))
				goto excessive;
			ah->frags[ah->nfrag].offset = ah->pos;
			ah->frags[ah->nfrag].len = 0;
			ah->frags[ah->nfrag].nfrag = 0;

			wsi->u.hdr.post_literal_equal = 0;
			ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] = ah->nfrag;
			wsi->u.hdr.ups = URIPS_IDLE;
			goto swallow;
		}

check_eol:
		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE &&
		    c == '\x0d') {
			if (wsi->u.hdr.ues != URIES_IDLE)
				goto forbid;

			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			//printf("*\n"); // \r after value of a given header
		}

		n = issue_char(wsi, c);
		if ((int)n < 0)
			return -1;
		if (n > 0)
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;

swallow:
		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
			goto set_parsing_complete;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		//printf("WSI_TOKEN_NAME_PART '%c' (mode=%d)\n", c, wsi->mode);

		wsi->u.hdr.lextable_pos =
				lextable_decode(wsi->u.hdr.lextable_pos, c);
#if 0
		/*
		 * Server needs to look out for unknown methods...
		 */
		if (wsi->u.hdr.lextable_pos < 0 &&
		    wsi->mode == LWSCM_HTTP_SERVING) {
			/* this is not a header we know about */
			for (m = 0; m < ARRAY_SIZE(methods); m++)
				if (ah->frag_index[methods[m]]) {
					/*
					 * already had the method, no idea what
					 * this crap from the client is, ignore
					 */
					wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
					break;
				}
			/*
			 * hm it's an unknown http method from a client in fact,
			 * treat as dangerous
			 */
			if (m == ARRAY_SIZE(methods)) {
				lwsl_info("Unknown method - dropping\n");
				goto forbid;
			}
			break;
		}
#endif //AA-
		/*
		 * ...otherwise for a client, let him ignore unknown headers
		 * coming from the server
		 */
		if (wsi->u.hdr.lextable_pos < 0) {
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			break;
		}

		if (lextable[wsi->u.hdr.lextable_pos] < FAIL_CHAR) {
			/* terminal state */

			n = ((unsigned int)lextable[wsi->u.hdr.lextable_pos] << 8) |
					lextable[wsi->u.hdr.lextable_pos + 1];

			//printf("known hdr %d\n", n);
			for (m = 0; m < ARRAY_SIZE(methods); m++)
				if (n == methods[m] &&
				    ah->frag_index[methods[m]]) {
					//printf("Duplicated method\n");
					return -1;
				}

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->u.hdr.parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);

			//AA-
			/*if (context->token_limits)
				wsi->u.hdr.current_token_limit =
					context->token_limits->token_limit[
						       wsi->u.hdr.parser_state];
			else*/
				wsi->u.hdr.current_token_limit =sizeof(wsi->u.hdr.ah->data);//1024
				//wsi->context->max_http_header_data; //AA-

			if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;

			goto start_fragment;
		}
		break;

start_fragment:
		ah->nfrag++;
excessive:
		if (ah->nfrag == ARRAY_SIZE(ah->frags)) {
			//printf("More hdr frags than we can deal with\n");
			return -1;
		}

		ah->frags[ah->nfrag].offset = ah->pos;
		ah->frags[ah->nfrag].len = 0;
		ah->frags[ah->nfrag].nfrag = 0;

		n = ah->frag_index[wsi->u.hdr.parser_state];
		if (!n) { /* first fragment */
			ah->frag_index[wsi->u.hdr.parser_state] = ah->nfrag;
			break;
		}
		/* continuation */
		while (ah->frags[n].nfrag)
			n = ah->frags[n].nfrag;
		ah->frags[n].nfrag = ah->nfrag;

		if (issue_char(wsi, ' ') < 0)
			return -1;
		break;

		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
		//printf("WSI_TOKEN_SKIPPING '%c'\n", c);

		if (c == '\x0d')
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;

	case WSI_TOKEN_SKIPPING_SAW_CR:
		//printf("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (wsi->u.hdr.ues != URIES_IDLE)
			goto forbid;
		if (c == '\x0a') {// \n
			wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.hdr.lextable_pos = 0;
		} else
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
		break;
		/* we're done, ignore anything else */

	case WSI_PARSING_COMPLETE:
		//printf("WSI_PARSING_COMPLETE '%c'\n", c);
		break;
	}

	return 0;

set_parsing_complete:
	if (wsi->u.hdr.ues != URIES_IDLE)
		goto forbid;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		//printf("v%02d hdrs completed\n", wsi->ietf_spec_revision);
	}
	wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return 0;

forbid:
	//printf(" forbidding on uri sanitation\n");
	//lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL); //AA-
	return -1;


}

#if 0
int main (int argc, char *argv[])

{
	char buf[]="GET / HTTP/1.1\r\nX-Forwarded-For: 12.12.12\r\nCookie: session=614141414110\r\nX-Cm-Token: 1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: cVA4L6lLENWjV6BtzTPKug==\r\nSec-WebSocket-Version: 13\r\nHost: xx.com:1970\r\nAccept-Encoding: gzip\r\nUser-Agent: okhttp/2.2.0\r\n\r\n";
	//char buf[]="GET / HTTP/1.1\r\nCookie: session=61414141410\r\nSec-WebSocket-Key: cVA4L6lLENWjV6BtzTPKug==\r\nHost: xx.com:1970\r\n\r\n";
	size_t len=strlen(buf);
	char *buf2=buf;
	void *context=NULL;
	struct lws *wsi=calloc(1, sizeof(struct lws));
	wsi->u.hdr.ah=calloc(1, sizeof(struct allocated_headers));
	wsi->u.hdr.parser_state=WSI_TOKEN_NAME_PART;
	wsi->state=2;//WSI_STATE_HTTP_HEADERS;

	while (len--)
	{

		if (ws_parse(context, wsi, *buf2++))
		{
			//printf("libwebsocket_parse failed\n");
			break;
		}
		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
				continue;
	}

	//int data_offset=wsi->u.hdr.ah->frag_index[3];

	int idx=1;
	for ( ; idx<=wsi->u.hdr.ah->nfrag; idx++)
	{
		int j=wsi->u.hdr.ah->frags[idx].offset;
		//printf("frag_offset:'%d'  len:'%d'  data: '%s' \n",
				wsi->u.hdr.ah->frags[idx].offset,
				wsi->u.hdr.ah->frags[idx].len,
				wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset);

	}

	idx=wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_COOKIE];//WSI_TOKEN_HTTP_COOKIE];
	//printf("WSI_TOKEN_HTTP_COOKIE(%d) idx='%d' frag_offset:'%d'  len:'%d' data: '%s' \n",
			WSI_TOKEN_HTTP_COOKIE, idx,
					wsi->u.hdr.ah->frags[idx].offset,
					wsi->u.hdr.ah->frags[idx].len,
					wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset);

	idx=wsi->u.hdr.ah->frag_index[WSI_TOKEN_HOST];//WSI_TOKEN_HTTP_COOKIE];
		//printf("WSI_TOKEN_HOST(%d) idx='%d' frag_offset:'%d'  len:'%d' data: '%s' \n",
				WSI_TOKEN_HOST, idx,
						wsi->u.hdr.ah->frags[idx].offset,
						wsi->u.hdr.ah->frags[idx].len,
						wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset);

		idx=wsi->u.hdr.ah->frag_index[X_FORWARDED_FOR];//WSI_TOKEN_HTTP_COOKIE];
				//printf("%s(%d) idx='%d' frag_offset:'%d'  len:'%d' data: '%s' \n",
						"X_FORWARDED_FOR",
						X_FORWARDED_FOR, idx,
								wsi->u.hdr.ah->frags[idx].offset,
								wsi->u.hdr.ah->frags[idx].len,
								wsi->u.hdr.ah->data+wsi->u.hdr.ah->frags[idx].offset);


}
#endif
