
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
void gen_sha1(Socket *, char *);

