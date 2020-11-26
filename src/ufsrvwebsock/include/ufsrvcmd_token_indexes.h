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

#ifndef SRC_INCLUDE_UFSRVCMD_TOKEN_INDEXES_H_
#define SRC_INCLUDE_UFSRVCMD_TOKEN_INDEXES_H_

/*
 * 	0)create a header file, defining the command tokens:  ufsrvcmd_lexer_strings.h
 * 	static const char *set[] = {
    	"/v1/keepalive",//0
		"/v1/verifynewaccount",//1
		"/v1/setaccountattributes",//2
		"/v1/accountgcm",//3
		"/v1/accountdirectory",//4
		"/v1/setkeys",//5
		"/v1/getkeys",//6
		"/v1/message",//7
	};
 *
 *	1)make sure minilex include the above file: gcc minilex.c -o minilex.ufsrv
 *	2)./minilex.ufsrv > ufrsvcmd_lexer.h
 *	3)inlude ufrsvcmd_lexer.h in relevant c file in an unsigned char array
 *		unsigned char lextable[] = {
		#include "ufrsvcmd_lexer.h"
		};
	4)define a corresponding enum with exactly the same position values or each command defined in
 * NOTE: These public enums are part of the abi.  If you want to add one,
 * add it at where specified so existing users are unaffected.
 *
 */

enum ufsrvcmd_token_indexes {
	UFSRVCMD_KEEPALIVE=0,
	UFSRVCMD_VERIFYACC=1,
	UFRSVCMD_SETACCATTR=2,
	UFRSVCMD_ACCGCM=3,
	UFRSVCMD_ACTIVITY_STATE=4,
	UFRSVCMD_SETKEY=5,
	UFRSVCMD_GETKEYS=6,
	UFRSVCMD_MSG=7,
	UFSRVCMD_LOCATION=8,
	UFSRVCMD_FENCE=9,
	UFSRVCMD_STATESYNC=10,
	//Add more here

	/* always last real token index*/
	WSI_TOKEN_COUNT,
};

#endif /* SRC_INCLUDE_UFSRVCMD_TOKEN_INDEXES_H_ */
