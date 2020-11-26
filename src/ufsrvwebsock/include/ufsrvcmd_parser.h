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

#ifndef INCLUDE_UFSRVCMD_PARSER_TYPE_H_
#define INCLUDE_UFSRVCMD_PARSER_TYPE_H_

#include <ufsrvcmd_token_indexes.h>//enum definition
#include <session_type.h>

#ifndef FAIL_CHAR
	#define FAIL_CHAR 0x08
#endif
#define UFSRVCMD_MAXLEN 128 //max length of command

/*
 * 	0)create a header file, defining the command tokens:  ufsrvcmd_lexer_strings.h
 * 	static const char *set[] = {
    	"/v1/keepalive",//0
      	"/v1/verifynewaccount",//1
      	"/v1/setaccountattributes",//2
      	 "", //not matchable
	};
 *
 *	1)(one-off) make sure minilex include the above file: gcc minilex.c -o minilex.ufsrv
 *	2)./minilex.ufsrv > ufsrvcmd_lexer_data.h
 *	3)inlude lextable-ufrsvcmd.h in relevant c file in an unsigned char array
 *		unsigned char lextable[] = {
		#include "lextable-ufrsvcmd.h"
		};
	4)ufsrvcmd_token_indexes.h define a corresponding enum with exactly the same position values or each command defined in
 * NOTE: These public enums are part of the abi.  If you want to add one,
 * add it at where specified so existing users are unaffected.
 *
 */


struct LexParserState {
	short lextable_pos;
	int match_found;
};

typedef struct LexParserState LexParserState;

int UfsrvCommandIndexGet (Session *sesn_ptr, const char *command_str);

#endif /* INCLUDE_USERS_H_ */
