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
#include <ufsrvcmd_parser.h>

unsigned char lextable_ufsrvcmd[] = {
	#include "ufsrvcmd_lexer_data.h"
};

inline static int
lextable_decode(int pos, char c)
{
	//AA+ if we exceed table size don't bother
	if (pos>=sizeof(lextable_ufsrvcmd)) return -1;

	if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';

		while (1) {
			if (lextable_ufsrvcmd[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
				if ((lextable_ufsrvcmd[pos] & 0x7f) != c)
					return -1;
				/* fall thru */
				pos++;
				if (lextable_ufsrvcmd[pos] == FAIL_CHAR)
					return -1;
				return pos;
			}

			if (lextable_ufsrvcmd[pos] == FAIL_CHAR)
				return -1;

			/* b7 = 0, end or 3-byte */
			if (lextable_ufsrvcmd[pos] < FAIL_CHAR) /* terminal marker */
				return pos;

			if (lextable_ufsrvcmd[pos] == c) /* goto */
				return pos + (lextable_ufsrvcmd[pos + 1]) +
							(lextable_ufsrvcmd[pos + 2] << 8);
			/* fall thru goto */
			pos += 3;
			/* continue */
		}
}

/**
 *  parses a given command and returns its corresponding callback function
 */
static inline int
_UfsrvCommandIndexGet (LexParserState *wsi, unsigned char c)
{
	//struct allocated_headers *ah = wsi->u.hdr.ah;
	  unsigned int n=0;

	  //we found a substring match earlier, but since we are reading more, we'll clear it
	  //since we are reading more advance the pos by one to allow for cases where token common
	  //prefixes. we dont want to bail oout on first occurrance
	  if (wsi->match_found>=0)
	  {
	    wsi->match_found=-1;

	     wsi->lextable_pos+=2;
	  }

	 {
	    //printf("WSI_TOKEN_NAME_PART '%c' (mode=%d)\n", c, 1);//wsi->mode);

	    wsi->lextable_pos=lextable_decode(wsi->lextable_pos, c);

	    /*
	     * bail out on unknown headers coming from the server
	     *
	     */
	    if (wsi->lextable_pos < 0)
	    {
	      return -1;
	    }

	    if (lextable_ufsrvcmd[wsi->lextable_pos] < FAIL_CHAR)
	    {
	      /* terminal state */
	      n = ((unsigned int)lextable_ufsrvcmd[wsi->lextable_pos] << 8) |
	          lextable_ufsrvcmd[wsi->lextable_pos + 1];

	      //this may be a match
	      //printf("known header %d\n", n);

	      //remember this first match. gets overwritten if we come back with more characters
	      wsi->match_found = n;
	    }
	  }

	  return n; //come back, or cmdidx

}

/**
 * 	@returns command index which is >=0. On error, -1.
 */
int
UfsrvCommandIndexGet (Session *sesn_ptr, const char *command_str)
{
	size_t len = strlen(command_str);
	if (len > UFSRVCMD_MAXLEN) {
		syslog(LOG_NOTICE, "%s: ERROR: COMMAND '%s' has length: '%lu' exceeding UFSRVCMD_MAXLEN: '%d'..", __func__, command_str, len, UFSRVCMD_MAXLEN);

		return -1;
	}

	LexParserState lps;
	lps.match_found=-1;
	lps.lextable_pos=0;

	ssize_t cmdidx=-1;

	const char *str=command_str;

	while (len--) {
		if ((cmdidx=_UfsrvCommandIndexGet(&lps, *str++))==-1) {
		  syslog(LOG_NOTICE, "%s: ERROR: COMMAND '%s' could be found...", __func__, command_str);
		  break;
		}
	}

	return cmdidx;

}



