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

#include <session_type.h>
#include <socket_message_type.h>
#include <socket_type.h>

#define BUFSIZE 65536
#define DBUFSIZE (BUFSIZE * 3) / 4 - 20

#define SERVER_HANDSHAKE_HIXIE "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
Upgrade: WebSocket\r\n\
Connection: Upgrade\r\n\
%sWebSocket-Origin: %s\r\n\
%sWebSocket-Location: %s://%s%s\r\n\
%sWebSocket-Protocol: %s\r\n\
\r\n%s"

#define SERVER_HANDSHAKE_HYBI "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\
Sec-WebSocket-Protocol: %s\r\n\
X-UFSRVCID: %lu\r\n\
X-UFSRVUID: %lu\r\n\
\r\n"

#define HYBI_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define HYBI10_ACCEPTHDRLEN 29

#define HIXIE_MD5_DIGEST_LENGTH 16

#define POLICY_RESPONSE "<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>\n"

int parse_handshake(Session *, char *);
int encode_hixie(u_char const *, size_t, char *, size_t); 
int decode_hixie(char *, size_t, u_char *, size_t, unsigned int *, unsigned int *, size_t *);
int encode_hybi(SocketMessage *, const unsigned char *, size_t, unsigned char *, size_t, unsigned int);
int decode_hybi(SocketMessage *, unsigned char *, ssize_t, unsigned char *, ssize_t, unsigned int *, unsigned int *);
int
encode_hybi_client	(SocketMessage *sm_ptr, const unsigned char *src, size_t srclength, unsigned char *target, size_t targsize, unsigned int opcode);
int decode_hybi_client(SocketMessage *, unsigned char *, ssize_t, unsigned char *, ssize_t, unsigned int *, unsigned int *);
int parse_hixie76_key(char * );
int gen_md5(Socket *, char *);
void gen_sha1(const char *, char *);

