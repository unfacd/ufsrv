/**
 * Copyright (C) 2015-2020 unfacd works
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

/**
 * Set of parsable strings (ALL LOWER CASE) used in the generation of the lexer parser for server-bound ufsrv commands.
 * Not used in the compilation of the main server; rather, as input for the minilex parser, which outputs
 * ufsrvcmd_lexer_data.h, which is what is used in compiling the server. See @file src/lexer/Makefile for additional details.
 */

static const char *set[] = {
		"/v1/keepalive",//0
			"/v1/call",//1
			"/v1/user",//2
			"/v1/accountgcm",//3
			"/v1/activitystate",//4
			"/v1/setkeys",//5
			"/v1/getkeys",//6
			"/v1/message",//7
			"/v1/location",//8
			"/v1/fence",//9
			"/v1/statesync",//10
			"", //35/* not matchable */

};
