/*
 *
 *  Created on: 19 Mar 2015
 *      Author: ayman
 */

#ifndef INCLUDE_UFSRVCMD_PARSER_TYPE_H_
#define INCLUDE_UFSRVCMD_PARSER_TYPE_H_
#include <ufsrvcmd_token_indexes.h>//enum definition
#include <session.h>

#ifndef FAIL_CHAR
	#define FAIL_CHAR 0x08
#endif
#define UFSRVCMD_MAXLEN 128 //max length of command

/*
 * 	0)create a header file, defining the command tokens:  ufsrv-cmd-strings.h
 * 	static const char *set[] = {
    	"/v1/keepalive",//0
      	"/v1/verifynewaccount",//1
      	"/v1/setaccountattributes",//2
      	 "", //not matchable
	};
 *
 *	1)make sure minilex include the above file: gcc minilex.c -o minilex.ufsrv
 *	2)./minilex.ufsrv > lextable-ufrsvcmd.h
 *	3)inlude lextable-ufrsvcmd.h in relevant c file in an unsigned char array
 *		unsigned char lextable[] = {
		#include "lextable-ufrsvcmd.h"
		};
	4)ufsrvcmd_token_indexes.h define a corresponding enum with exactly the same position values or each command defined in
 * NOTE: These public enums are part of the abi.  If you want to add one,
 * add it at where specified so existing users are unaffected.
 *
 */

#if 0
//defined in own header file with same enum name
enum ufsrvcmd_token_indexes {
	UFSRVCMD_KEEPALIVE=0,
	UFSRVCMD_VERIFYACC=1,
	UFRSVCMD_SETACCATTR=2,
	//Add more here

	/* always last real token index*/
	WSI_TOKEN_COUNT,
};
#endif

struct LexParserState {
	short lextable_pos;
	int match_found;
};

typedef struct LexParserState LexParserState;

int UfsrvCommandIndexGet (Session *sesn_ptr, const char *command_str);

#endif /* INCLUDE_USERS_H_ */
