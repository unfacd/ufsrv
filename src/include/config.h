/* src/include/config.h.  Generated from config.h.in by configure.  */
#ifndef CONFIG_H
# define CONFIG_H

#define _REENTRANT
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#ifndef __GNUC__
#define __attribute__(a)
#endif

//enable for highest debug level
//#define	__UF_FULLDEBUG
#define	__UF_TESTING	1	//turn off in production
#define	__UF_DEV		1	//turn off in production
//#define __UF_FULLDEBUG 0

//see delegator
#define	CONFIG_USE_LOCKLESS_NEW_CONNECTIONS_QUEUE	1
#define CONFIG_USE_LOCKLESS_SESSION_WORKERS_QUEUE	1
#define CONFIG_USE_LOCKLESS_UFSRV_WORKERS_QUEUE		0
#define CONFIG_USE_ANDERSON_SPINLOCK							1
#define CONFIG_SESSION_INSERVICE_MAX_TIMEOUT			20 //in seconds session is considred stale if its state in marked as inservice for longer than this amount of time
//#define CONFIG_USE_OPTIK_LOCK											0

#define CONFIG_LOCKLESS_UFSRV_WORKER_QUEUE_SIZE		512	//bounded job queue per thread
#define CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE	512	//bounded job queue per thread

//buffer size of the the ne connections pipe and the threshold at which the pipe is read from
#define CONFIG_NEW_CONNECTIONS_PIPE_SIZE							1024
#define CONFIG_NEW_CONNECTIONS_PIPE_DRAIN_THREASHOLD	1000
#define CONFIG_MMSG_MAX_PACKET_SIZE 									8192 //for recvmmsg

#define CONFIG_FILE_NAME "ufsrv.conf"
#define MASTER_LOG_FILE_NAME "ufsrv.log"
#define CONFIG_DIR "/etc/ufsrv"
#define CONFIG_PID_DIR "/var/run/ufsrv"
#define _TMP_DIR	"/tmp"
#define MAXHOSTLEN  165
#define CONFIG_MAX_VERIFICATION_CODE_FORMATTED_SZ			7	//xxxx-xxxx
#define CONFIG_MAX_VERIFICATION_CODE_SZ								6 //max number of digits in the verification code
#define CONFIG_MAX_COOKIE_SZ													64
#define CONFIG_MAX_REGOCOOKIE_SZ											32
#define CONFIG_MAX_FENCELIST_SZ	256 //max number of fence membership allowed for a given user
#define CONFIF_MAX_UFSRV_INSTANCE_PER_GEOGROUP				512 //temporary max ceiling on number of allowed server instance per region
#define _CONFIGDEFAULT_DEFAULT_UFSRVGEOGROUP					3		//fallback ufsrv geogroup to use if user doesn have valid group
#define CONFIG_UFSRV_UID															1		//system uid for ufrsv owned assets
#define CONFIG_MAX_UFSRV_ID_SZ												16	//16 bytes of id
#define CONFIG_MAX_UFSRV_ID_ENCODED_SZ								26	//in bytes when id is encoded in  Crockford's Base32. 01020CA9CT9G86G08000000000

#define CONFIG_DBBACKEND_DBNAME "ufsrv"
#define CONFIG_E164_NUMBER_UFSRV_COUNTRY_PREFIX				"+800"
#define CONFIG_UNSPECIFIED_E164_NUMBER               "+8000000000000" //ensure client is using the same
#define CONFIG_E164_NUMBER_VALUE_MAX                  9999999999//10 digits
#define CONFIG_E164_NUMBER_VALUE_DIGITS_COUNT         10 //excluding country prefix
#define CONFIG_E164_NUMBER_SZ_MAX                     20 //15 digits number + 5 country code
#define CONFIG_EMAIL_ADDRESS_SZ_MAX                   254 //https://tools.ietf.org/html/rfc5321#section-4.5.3

#define _CONFIGDEFAULT_INTRA_UFSRV_CLASSNAME		      "ufsrv"	//classname for the class of servers that handle intra commands
#define CONFIG_MAX_FENCE_NAME_SIZE										128
#define CONFIG_MAX_NICKNAME_SIZE											64
#define CONFIG_MAX_FAVATAR_SIZE												128 //fence avatar reference
#define CONFIG_MAX_INVITE_SET_SIZE										128	//user can include that many invitees per one command invocation
#define _CONFIGDEFAULT_ATTACHMENT_NONCE_EXPIRY				1800	//(seconds) 30 minutes to allow for slow uploads
#define	CONFIG_MAX_NONCE_SZ														(SHA_DIGEST_LENGTH+UINT64_LONGEST_STR_SZ)
#define _CONFIGDEFAULT_GEOLOC_FUZZFACTOR							500.0		//meters radius
#define CONFIG_FENCE_PERMISSIONS_PFACTOR 							6 //64 buckets initial size factor for hopscotch hash table size (this will be raised to power of 2)
#define CONFIG_THREAD_LOCKED_OBJECTS_STORE_PFACTOR 							6 //64 buckets initial size factor for hopscotch hash table size (this will be raised to power of 2)
#define CONFIG_FENCE_PERMISSIONS_KEYLEN								sizeof(unsigned long)
#define CONFIG_FENCE_PERMISSIONS_KEYOFFSET(x, y)			offsetof(x, y)
#define CONFIG_PREFERENCE_PREFIX											"pref_"
#define CONFIG_DEFAULT_BOOLPREFS_VALUE                192 //turns on offsets 0 an 1
#define CONFIG_DEFAULT_PREFS_INT_VALUE                0
#define CONFIG_DEFAULT_PREFS_STRING_VALUE             "*"
#define CONFIG_USER_PROFILEKEY_MAX_SIZE								32 //profile key binary size
#define CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED				57 //CONFIG_USER_PROFILEKEY_MAX_SIZE+1)/3)*5
#define CONFIG_USER_ACCESS_TOKEN_MAX_SIZE							16 //access token binary size
#define CONFIG_USER_ACCESS_TOKEN_MAX_SIZE_ENCODED			32 //access token encoded size

#define CONFIG_CM_TOKEN_SZ_MAX                        255 //GCM token sizes
#define CONFIG_CM_TOKEN_UNDEFINED                     '*'

//START NONPUBLIC
#include <config_nonpublic.h>
//END NONPUBLIC

//max session allocation groups for this server instance
#define _MEMSPECS_SESSION_ALLOCGROUPS 10
//number of sessions per allocation group
#define _MEMSPECS_SESSION_ALLOCGROUP_SZ	1024
//when we are 90% full across total allocation, andprovided we have room to grow, allocate new sessions group
#define _MEMSPECS_SESSION_ALLOC_TRIGGER_THRESHOLD	"10%"

//fixed array for the main listened new connection queue
#define _CONFIG_LISTENER_CONNECTION_QUEUE_SZ 1024

#define _CONFIGDEFAULT_BACKENDCACHE_PORT_SESSION	21000
#define _CONFIGDEFAULT_BACKENDCACHE_HOST_SESSION	"127.0.0.1"
#define _CONFIGDEFAULT_BACKENDCACHE_PORT_USRMSG		22000
#define _CONFIGDEFAULT_BACKENDCACHE_HOST_USRMSG		"127.0.0.1"
#define _CONFIGDEFAULT_BACKENDCACHE_PORT_FENCE		23000
#define _CONFIGDEFAULT_BACKENDCACHE_HOST_FENCE		"127.0.0.1"
#define _CONFIGDEFAULT_BACKENDCACHE_PORT_MSGQUEUE		24000
#define _CONFIGDEFAULT_BACKENDCACHE_HOST_MSGQUEUE		"127.0.0.1"

//How often to run the timeout checker job in seconds
//#define _CONFIGDEDAULT_IDLE_TIME_INTERVAL	60//seconds
#define _CONFIGDEDAULT_IDLE_TIME_INTERVAL	100000//usec (100 millisec)
#define _CONFIGDEFAULT_SESSION_TIMEOUT_CHECK_FREQUENCY	60000000 //in micoro seconds 1 min
#define _CONFIGDEFAULT_FENCE_ORPHANED_CHECK_FREQUENCY		120000000	//300000000 //in micoro seconds 5 min

#define _CONFIGDEFAULT_ETAG_SIZE					32

#define _CONFIGDEFAULT_IDLETIME_THRESHOLD 	5 //number of seconds elapsed without heartbeat from client before connection is deemed disconnected

#define _CONFIG_SENDER_CERTIFICATE_EXPIRYTIME         86400000 //1 day in millis

#define _CONFIG_CACHE_BACKEND_RECONNECT_SLEEP         100000000 //in nano second -> 100ms
#define _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_USEC      0//500000 //0.5sec
#define _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_SEC       5

//default value for maximum io session worker threads to spawn. corresponding configfile value: .session_workers_thread_pool'
#define _CONFIGDEFAULT_MAX_SESSION_WORKERS 2

//default value for maximum ufserver worker threads to spawn. corresponding configfile value: ufsrv_workers_thread_pool
#define _CONFIGDEFAULT_MAX_UFSRV_WORKERS 3

//how much to read by default. read size is dynamically adjusted depending how volume of read and how sustained that is
#define _BUFFER_DEFAUL_BLOCKSZ	2048//2K

//default max read block size that can be dynamically adjusted. both can be overriden in config file
#define _BUFFER_MAX_BLOCKSZ 1024000 //1MB

//to use with setsockopt SO_RCVBUF and SO_SNDBUF
#ifdef __gnu_linux__
#define _CONFIG_LARGE_SOCK_SIZE 33554431
#else
#define _CONFIG_LARGE_SOCK_SIZE 4096
#endif

#define INT16_LONGEST_STR	"-32768"
#define UINT16_LONGEST_STR	"65535"
#define INT32_LONGEST_STR 	"-2147483648"
#define UINT32_LONGEST_STR 	"4294967295"
#define INT64_LONGEST_STR 	"-9223372036854775808"
#define UINT64_LONGEST_STR 	"18446744073709551615"
#define UINT64_LONGEST_STR_SZ 	20

#define _CONFIGDEFAULT_DEFAULT_UFSRVMEDIA_UPLOAD_URI "https://media.unfacd.io/"
#define _CONFIGDEFAULT_DEFAULT_UFSRVMEDIA_STORAGE_LOCATION "/ufsrv_media/"

//131071
#define _CONFIGDEFAULT_HASHTABLE_SZ							65521
#define _CONFIDEFAULT_HASHTABLE_BASICAUTH_SZ		2//10009//this should be configurable load time as well
#define _CONFIDEFAULT_HASHTABLE_ATTACHMENTS_SZ	65521//10009//this should be configurable load time as well

/*
 * Glibc's pid_t is implemented as a signed
 * 32bit integer, for both 32 and 64bit systems - max value: 2147483648.
 */
#define MAXPIDLEN 10

//when encoding user number for network directory listing cap encoding to this amount of bytes
#define USER_NUMBER_SHA_1_TOKEN_LIMIT 14

//size of verification code generated for new registrations: 'xxx-xxx'
#define _VERIFICATION_CODE_SZ	7

#define _NONCE_NAME	"nonce"
//used when setting nonce in redis
#define _OPEN_NONCE_PREFIX	"_OPEN"
//valid for..
#define _OPEN_NONCE_TTL	30 /*seconds*/

#define _ACCOUNT_NONCE_PREFIX	"_ACCOUNT"
#define _ACCOUNT_NONCE_TTL	30

//has prefix for fetching user binary blobs
#define _ATTCHMENT_DOWNLOAD_PREFIX "_USERBLOB"

#define _BASICAUTH_PREFIX	"_BASICAUTH"
#define _BASICAUTH_CACHE_EXPIRY	86400UL //one day

//set underwhich all registered nicknames are kept for quick lookup
#define _NAMESPACE_BACKEND_NICKNAMES_DIRECTORY	"_NICKNAMES_DIRECTORY"

//set underwhich all registered username tokens are kept for quick lookup
#define _NAMESPACE_BACKEND_ACCOUNTS_DIRECTORY	"ACCOUNTS_DIRECTORY"

//when user makes a PUT request for endpoint /V1/Attachment, this request heade must be present
#define _ATTACHMENT_HEADER_NONCE  "X-UFSRV-ATTACHMENT-NONCE"
#define HTTP_HEADER_COOKIE        "X-Ufsrv-Cookie"

#define __VALGRIND_DRD 1
#define __VALGRIND_MEMCHECK	1
/* configuration */


#ifdef __GLIBC__
#	if ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
#		define HAVE_RECVMMSG 1
#	endif
#endif

#define HAVE_SA_LEN  		0
#define HAVE_HSTRERROR 	1
#define HAVE_INET_PTON	1
#define HAVE_INET_NTOP	1

#endif
