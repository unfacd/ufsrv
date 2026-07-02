/*
 *
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <ufsrvmsg_core/include/net.h>
#include <session.h>
#include <unistd.h>
#include <ufsrvmsg_core/protocol/protocol_type.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include "protocol_websocketclient.h"
#include <sessions_delegator_type.h>
#include "ufsrvapi_endpoints.h"

static SessionsDelegator sessions_delegator;
SessionsDelegator *const sessions_delegator_ptr=&sessions_delegator;

static ufsrv master;
ufsrv *const masterptr=&master;

const char *c_version="1";

static  Protocol ProtocolsRegistry []={

{
 "WebSocketsClient", 0, ThreadWebSockets,
 {
	NULL,//proto init
	NULL,//session init
	NULL,//proto_websocket_reset_callback,
	NULL,//proto_websocket_hanshake_callback,
	NULL,//proto_websocket_post_hanshake_callback,
    proto_websocketclient_msg_callback,
	proto_websocketclient_decode_msg_callback, //decode
	NULL,//encode
    NULL,//proto_websocket_error_callback,
    NULL//proto_websocket_close_callback
 },
 0, NULL,
 {
	1,//unsigned read_blocked_session
	1,//unsigned read_inservice_session
	1,//retain_session_on_error
	1//_PROTOCOL_CTL_ABORT_IOERROR
 }//end of struct
}//end of array entry

,
{
 "", -1, NULL, {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}, 0, NULL, {0, 0, 0}
}
};

static int deny_mux;
static volatile int force_exit = 0;
static int longlived = 0;

static pthread_mutex_t *lockarray; //openssl
static void init_locks(void);
static void kill_locks(void);

const Protocol *const protocols_registry_ptr=ProtocolsRegistry;
unsigned protocols_count=sizeof(ProtocolsRegistry)/sizeof(Protocol);


void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",      required_argument,      NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "version",	required_argument,	NULL, 'v' },
	{ "undeflated",	no_argument,		NULL, 'u' },
	{ "nomux",	no_argument,		NULL, 'n' },
	{ "longlived",	no_argument,		NULL, 'l' },
	{ NULL, 0, 0, 0 }
};

enum args {
    ARGS_FAILED,
    ARGS_USE_CONFIG,
    ARGS_SERVE_FILES
};

typedef struct UfcltConfigOptions {
	int 	workers_size;
	int		destination_port;
	int		use_tls:1;
	int		persist_to_file:1;
	int		persist_to_redis:1;
	int		resumption_mode:1;
	char 	*destination_server;
	char 	*persistance_file_name;
	char 	*persistance_file_location;
	char 	*persistance_redis_server;
	int		persistance_redis_port;
	char 	*resumption_handle;
} UfcltConfigOptions;


UfcltConfigOptions CanonicalOptions = {
		.workers_size=1,
		.destination_port=190701,
		.use_tls=0,
		.persist_to_file=0,
		.persist_to_redis=0,
		.resumption_mode=0,
		.destination_server="127.0.0.1",
		.persistance_file_name=NULL,
		.persistance_file_location="/tmp/",
		.persistance_redis_server=NULL,
		.persistance_redis_port=0,
		.resumption_handle=NULL
};

#if 1
static enum args
parse_args(int argc, char *argv[],  char *root)
{
    static const struct option opts[] = {
        { .name = "listen", 	.has_arg = 1,	.val = 'l' },
        { .name = "help", 						.val = 'h' },
        { .name = "workers", 	.has_arg = 1, 	.val = 'w' },
		{ .name = "resume", 	.has_arg = 1, 	.val = 'r' },
		{ .name = "port", 		.has_arg = 1, 	.val = 'p' },
		{ .name = "server", 	.has_arg = 1, 	.val = 's' },
        { }
    };
    int c, optidx = 0;
    enum args result = ARGS_USE_CONFIG;

    while ((c = getopt_long(argc, argv, "hr:l:cps:", opts, &optidx)) != -1) {
        switch (c) {
        case 'w':
			CanonicalOptions.workers_size= atoi(optarg);
			result = ARGS_USE_CONFIG;
			break;

        case 'p':
            CanonicalOptions.destination_port=atoi(optarg);
            break;

        case 'r': {
            CanonicalOptions.resumption_handle=strdup(optarg);
            CanonicalOptions.resumption_mode=1;
            break;
        }

        case 'h':
#if 0
            printf("Usage: %s [--root /path/to/root/dir] [--listener addr:port]\n", argv[0]);
            printf("\t[--config]\n");
            printf("Serve files through HTTP.\n\n");
            printf("Defaults to listening on %s, serving from ./wwwroot.\n\n", config->listener);
            printf("Options:\n");
            printf("\t-r, --root      Path to serve files from (default: ./wwwroot).\n");
            printf("\t-l, --listener  Listener (default: %s).\n", config->listener);
            printf("\t-c, --config    Path to config file path.\n");
            printf("\t-h, --help      This.\n");
            printf("\n");
            printf("Examples:\n");
            printf("  Serve system-wide documentation: %s -r /usr/share/doc\n", argv[0]);
            printf("        Serve on a different port: %s -l '*:1337'\n", argv[0]);
            printf("\n");
            printf("Report bugs at <https://github.com/lpereira/lwan>.\n");
#endif
            return ARGS_FAILED;

        default:
            printf("Run %s --help for usage information.\n", argv[0]);
            return ARGS_FAILED;
        }
    }

    return result;
}
#endif

Protocol *ProtocolGet (unsigned protocol_id)
 {
	 if (protocol_id>protocols_count-1)	return NULL;

	 return &ProtocolsRegistry[protocol_id];
 }

int main(int argc, char **argv)
{
	int n = 0;
	SSL_CTX **_ctx=calloc(1, sizeof(SSL_CTX *));

	SSL_CTX *ctx=_ctx[0];

	pthread_t *session_worker_ths;
	int setsize=1;

	if (argc < 2)
		goto usage;

	while (n >= 0)
	{
		n = getopt_long(argc, argv, "nuv:hsp:d:l", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'd':
			setsize=atoi(optarg);
			break;
		case 's':
			//use_ssl = 2; /* 2 = allow selfsigned */
			break;
		case 'p':
			setsize = atoi(optarg);
			break;
		case 'l':
			longlived = 1;
			break;
		case 'v':
			//ietf_version = atoi(optarg);
			break;
		case 'u':
			//deny_deflate = 1;
			break;
		case 'n':
			deny_mux = 1;
			break;
		case 'h':
			goto usage;
		}
	}

	if (optind >= argc)
	{
		usage:
		fprintf(stderr, "Usage: libwebsockets-test-client "
						"<server address> [--port=<p>] "
						"[--ssl] [-k] [-v <ver>] "
						"[-d <log bitfield>] [-l]\n");
			return 1;
	}

	struct timeval time_in;
	SeedRandom (&time_in);

	signal(SIGINT, sighandler);

	setsize = atoi(argv[optind]);

	char root[PATH_MAX];
	if (!getcwd(root, PATH_MAX))   return 1;

	openlog("ufclt", LOG_NDELAY, LOG_DAEMON);

	/*{
		if(SSL_library_init() < 0)
		{
		    fprintf(stderr, "Could not initialize the OpenSSL library !\n");
		    _exit(-1);
		}

		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		if ( (ctx=SSL_CTX_new(SSLv23_method()))==NULL)
		{
		    fprintf(stderr, "Unable to create a new SSL context structure.\n");
		    _exit(-1);
		}

		const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(ctx, flags);
		//Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_client_cert_cb(ctx, NULL);
		SSL_CTX_set_mode (ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
		SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
	}*/


	{
		extern void *ThreadClient (void *);

		//SSL
		init_locks();

		session_worker_ths=malloc(sizeof(pthread_t)*setsize);
		if (session_worker_ths==NULL)
		{
			syslog(LOG_ERR, "%s: FATAL: could not allocate memory for Session Worker Threads (requested: '%d'): terminating...", __FILE__, setsize);
			exit (-1);
			//d3 restored and updated with __FILE__
		}

		int i;
		int result;
		for (i=0; i!=setsize; i++)
		{
			result=pthread_create( &(session_worker_ths[i]), NULL, ThreadClient, (void *)ctx);
			if (result!=0)
			{
				fprintf(stderr, "SpawnIOSessionWorkers: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%d'): terminating...", setsize, i);
				exit (-1);
			}
	   }//for

		fprintf(stderr, "SpawnIOSessionWorkers: SUCCESSFULLY spawned '%d' Session Worker Threads...", setsize);

		/* now wait for all threads to terminate */
		  for(i=0; i!= setsize; i++)
		  {
		    int error_pth = pthread_join(session_worker_ths[i], NULL);
		    fprintf(stderr, "Thread %d terminated. Error: '%d'\n", i, error_pth);
		  }

		  //SSL
		  kill_locks();

		  return 0;
		 //pthread_exit(0);
		 //SSL_CTX_free(ctx);
	}


}

static void lock_callback(int mode, int type, char *file, int line)
{
  (void)file;
  (void)line;
  if(mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}

static unsigned long thread_id(void)
{
  unsigned long ret;

  ret=(unsigned long)pthread_self();
  return ret;
}

static void init_locks(void)
{
  int i;

  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                            sizeof(pthread_mutex_t));
  for(i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]), NULL);
  }

  CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void kill_locks(void)
{
  int i;

  CRYPTO_set_locking_callback(NULL);
  for(i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));

  OPENSSL_free(lockarray);
}
