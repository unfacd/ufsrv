/*
 * log_message_literals.h
 *
 *  Created on: 31 Jul 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_LOG_MESSAGE_LITERALS_H_
#define SRC_INCLUDE_LOG_MESSAGE_LITERALS_H_



enum {
	LOGCODE_MAINLISTENER=80,
	LOGCODE_MAINLISTENER_ACCEPT_ERROR=81, LOGCODE_MAINLISTENER_ACCEPT_QUEUED=82,LOGCODE_MAINLISTENER_PIPE_WRITE_ERROR=83,
	LOGCODE_MAINLISTENER_PIPE_WRITE_BLOCKING=84,

	LOGCODE_WDELEG=100,/* Main WorkRDelegator*/
		LOGCODE_WDELEG_NEWCONNECTION_ADDED=101,LOGCODE_WDELEG_WORKREQUEST_ADDED=102,LOGCODE_WDELEG_NONCONNECTED_REQUEST=103,
		LOGCODE_WDELEG_WORKER_REQUEST_RCV=104, LOGCODE_WDELEG_WORKERREAD_ERR=105,LOGCODE_WDELEG_WORKERREAD_SUCCESS=106,
		LOGCODE_WDELEG_WORKER_NULLREQUEST=107,	LOGCODE_WDELEG_EVENTS_POLLERROR=108,

	LOGCODE_MQDELEG=200,/*Main MsgQueue Delegator*/

	LOGCODE_TSWORKER=400, /*Session IO Thread Worker*/
		LOGCODE_TSWORKER_FAULTYSESN_OOB=401/*before being locked*/, LOGCODE_TSWORKER_FAULTYSESN=2,LOGCODE_TSWORKER_FAULTYSESN_COULDNTLOCK=3,
		LOGCODE_TSWORKER_QUEUEDIOERR=404,LOGCODE_TSWORKER_POLLERR=405,LOGCODE_TSWORKER_POLLERR_IN=406,LOGCODE_TSWORKER_HARD_SUSPEND=407,
		LOGCODE_TSWORKER_WDP_MISSING_OBJ=408,LOGCODE_TSWORKER_WDP_BROEKN_WRITE=409,LOGCODE_TSWORKER_WDP_SUCCESS_WRITE=410,
		LOGCODE_TSWORKER_QUEUE_POST_REQUEST=411,LOGCODE_TSWORKER_BACKEND_INSTANTIATE=412,

	LOGCODE_UFSRVWORKER=500, /*Ufsrv Worker Thread Worker*/
		LOGCODE_UFSRVWORKER_ONETHREADONLY=501,

	LOGCODE_THREADING=800, /*LOCKING*/
		LOGCODE_RDLOCK_SUCCESS=801, LOGCODE_LOCK_SUCCESS=802, LOGCODE_RWLOCK_SUCCESS=803, LOGCODE_UNLOCK_SUCCESS=804,
		LOGCODE_RDLOCKTRY_SUCCESS=806, LOGCODE_RWLOCKTRY_SUCCESS=807, LOGCODE_LOCKTRY_SUCCESS=808,
		LOGCODE_LOCK_FAIL=809, LOGCODE_RDLOCK_FAIL=810, LOGCODE_RWLOCK_FAIL=811, LOGCODE_UNLOCK_FAIL=812,
		LOGCODE_LOCKTRY_FAIL=814, LOGCODE_RWLOCKTRY_FAIL=814, LOGCODE_RDLOCKTRY_FAIL=815,
		LOGCODE_THREADCREATE_SUCCESS=810, LOGCODE_THREADCREATE_ERROR=811,

	LOGCODE_IO=900,
		LOGCODE_IO_BLOCKING=901,LOGCODE_IO_ERROR=902, LOGCODE_IOERR_NOTOWNER=903,
		LOGCODE_IO_BFRAG=904, LOGCODE_IO_QUEING=905, LOGCODE_IO_QUEINGEXC=906,
		LOGCODE_IO_BUF_CONSOLIDATED_PRE=907, LOGCODE_IO_BUF_CONSOLIDATED=908,LOGCODE_IO_BLOCKING_READ_NO_SESNLOCK=909, LOGCODE_IO_BUF_CONSOLIDATION_ERR=910,
		LOGCODE_IO_BUF_CONSOLIDATED_FIN=911, LOGCODE_IO_MSGQ_ADD_NODECODE=912, LOGCODE_IO_INVALID_READ_FD=913,LOGCODE_IO_BLOCKING_READ_WITH_RAW=914,
		LOGCODE_IO_ERROR_READ_WITH_RAW=915,LOGCODE_IO_READING_MSGQUE_BUF=916,LOGCODE_IO_READ_MSGQUE_BUF_QUEEMPTY=917,
		LOGCODE_IO_READ_MSGQUE_NOTCONSOLIDATED=918,
		LOGCODE_IO_RL_EXCEEDED_RATE_ACTIONS=919, LOGCODE_IO_RL_EXCEEDED_ACTIONS=920,LOGCODE_IO_ZERO_READ_WITH_RAW_EMPTY=921,

	LOGCODE_PROTO=1000,
		LOGCODE_PROTO_MISSING_PARAM=1001, LOGCODE_PROTO_INCONSISTENT_STATE=1002, LOGCODE_PROTO_COMMAND_MISSING=1003, LOGCODE_PROTO_COMMAND_FOUND=1004,
		LOGCODE_PROTO_COMMAND_TYPE_ERROR=1005,LOGCODE_PROTO_COMMAND_UNPACK_ERROR=1006, LOGCODE_PROTO_COMMAND_ENVELOPE_MISSING=1007,

	LOGCODE_CACHE=1100,
		LOGCODE_CACHE_SIZE_SESSION=1101,LOGCODE_CACHE_INCONSISTENT_SIZE=1102,LOGCODE_CACHE_EXTRACTEDSET_SIZE=1103,

	LOGCODE_SESSION=1200,
		LOGCODE_SESSION_SUSPEND_HARD=1201, LOGCODE_SESSION_SUSPEND_SOFT=1202,LOGCODE_SESSION_SUCCESS_MIGRATED=1203,LOGCODE_SESSION_ERROR_MIGRATED=1204,
		LOGCODE_SESSION_SUCCESS_REFRESHED_BKEND=1205,LOGCODE_SESSION_ERROR_REFRESHED_BKEND=1206,LOGCODE_SESSION_NOTONLINE_INITIALISING=1207,
		LOGCODE_SESSION_DISTRIBUTED_ID_GENERATED=1208, LOGCODE_SESSION_MISSING_FENCE=1209, LOGCODE_SESSION_EVENET_ID_ERROR_BACKEND=1210,

		LOGCODE_RECYCLER=1300,
		LOGCODE_RECYCLER_ENQUE_REFCNT_SHORT=1301,LOGCODE_RECYCLER_GET_FULLY_LEASED=1302,LOGCODE_RECYCLER_PUT_ON_FULL=1303,LOGCODE_RECYCLER_ENQUE_SUCCESS=1304,LOGCODE_RECYCLER_DEQUE_SUCCESS=1305,
		LOGCODE_RECYCLER_ENQUE_ERROR=1306,LOGCODE_RECYCLER_DEQUE_ERROR=1307,LOGCODE_RECYCLER_UNDEFINED_GROUPALLOC=1308,LOGCODE_RECYCLER_UNDEFINED_POOLDEF=1309,
		LOGCODE_RECYCLER_QUEUE_ITEM_REFCOUNT_ERROR=1310, LOGCODE_RECEYCLER_ALLOC_GROUP_IDX_ERR=1311,LOGCODE_RECYCLER_MAX_ALLOC_CAPACITY_REACHED=1312,
		LOGCODE_RECYCLER_ALLOC_GROUP_EXPANDED=1313, LOGCODE_RECYCLER_UNCOLLECTED_INSTANCES=1314, LOGCODE_RECYCLER_INSTANCE_NOT_ON_LIST=1315, LOGCODE_RECYCLER_MARSHALLER_INSTANCE=1316,
    LOGCODE_RECYCLER_NEW_INSTANCE_ERROR=1217,

	LOGCODE_ACCOUNT=1400,
		LOGCODE_ACCOUNT_INVALID_SIGNON_COOKIE=1401,LOGCODE_ACCOUNT_VERIFICATION_CODE_MISMATCH=1402,
		LOGCODE_ACCOUNT_ATTCH_PATH_INVALID=1403,LOGCODE_ACCOUNT_ATTCH_NO_MATCH=1404,LOGCCODE_ACCOUNT_ATTCH_NO_REQUEST_NONCE=1405,
		LOGCODE_ACCOUNT_ATTCH_DOWNLOADED_SUCCESS=1406,LOGCODE_ACCOUNT_IDKEY_ERROR=1407,LOGCODE_ACCOUNT_SIGNED_PREKEY_ERROR=1408,
		LOGCODE_ACCOUNT_PREKEY_ERROR=1409,LOGCODE_ACCOUNT_LASTRESORTKEY_ERROR=1410,

	LOGCODE_BACKENDCACHE=1500,
		LOGCODE_BACKENDCACHE_ERROR_REPLYOBJECT=1501, LOGCODE_BACKENDCACHE_ERROR_REPLYTYPE=1502, LOGCODE_BACKENDCACHE_NIL_REPLY=1503,
		LOGCODE_BACKENDCACHE_REPLY=1504, LOGCODE_BACKENDCACHE_UNSPECIFIED_REPLY=1505, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT=1506,
		LOGCODE_BACKENDCACHE_SHARED_CONTACTS_MIS=1507,LOGCODE_BACKENDCACHE_SHARED_CONTACTS_FOUNDNONE=1508,LOGCODE_BACKENDCACHE_SHARED_CONTACTS_TOTALFOUND=1509,

	LOGCODE_BACKENDDB=1600,
	LOGCODE_BACKENDDB_QUERY_STRING=1601, LOGCODE_BACKENDDB_CONNECTION_ERROR=1602,LOGCODE_BACKENDDB_EMPTY_RESULTSET=1603,

	LOGCODE_FENCE=1700,
	LOGCODE_FENCE_EVENET_ID_ERROR_BACKEND=1701, LOGCODE_FENCE_BACKEND_USERLIST_MISMATCH=1702, LOGCODE_FENCE_MISSING_SESSION=1703
};

#define LOGSTR_MAINLISTENER_ACCEPT_ERROR "%s {port:'%d, 'errno:'%d', error:'%s' e:'%d'}: ! ERROR: COULD NOT ACCEPT NEW CONNECTION"
#define LOGSTR_MAINLISTENER_ACCEPT_QUEUED	"%s {cid_new='%lu', o='%p', fd='%d', queue_sz:'%lu', e:'%d'}: CONNECTIONS QUEUE: Added new connection"
#define LOGSTR_MAINLISTENER_PIPE_WRITE_ERROR	"%s {errno:'%d', e:'%d'}: !ERROR: NEW CONNECTIONS PIPE: COULD NOT WRITE TO WORK DELEGATOR: HAS DELEATOR DIED?"
#define LOGSTR_MAINLISTENER_PIPE_WRITE_BLOCKING	"%s {errno:'%d', e:'%d'}: !ERROR: NEW CONNECTIONS PIPE BLOCKED: COULD NOT WRITE TO WORK DELEGATOR: HAS DELEATOR DIED?"

#define LOGSTR_FUNC_ENTERY "%s {pid:'%lu', o:'%p', cid:'%lu', e:'0'}: ENTERED: '%s'"
#define LOGSTR_NULL_PARAM "%s {pid:'%lu', e:'%d'}: ERROR: NULL PARAMETER:'%s'"
#define LOGSTR_INCONSISTENT_STATE "%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'}: NOTICE: INCONSISTENT STATE: '%s'"

#define LOGSTR_IO_BLOCKING_READ	"%s {pid:'%lu', o:'%p', cid:'%lu', errno:'%d', e:'%d'}: BLOCKING READ: Returning"
#define LOGSTR_IO_BLOCKING_READ_WITH_RAW	"%s {pid:'%lu', o:'%p', cid:'%lu', errno:'%d', raw_msg_sz:'%lu', e:'%d'}: BLOCKING READ: Have consolidated buffer: Continuing"
#define LOGSTR_IO_ERROR_READ_ZERO	"%s {pid:'%lu', o:'%p', cid:'%lu', raw_msg_sz:'%lu', e:'%d'}: IO TERMINATED: READ ZERO BYTES: NON-EMPTY Consolidated Buffer: Processing"
#define LOGSTR_IO_ERROR_READ_ZERO_EMPTY	"%s {pid:'%lu', o:'%p', cid:'%lu', raw_msg_sz:'%lu', e:'%d'}: IO TERMINATED: READ ZERO BYTES: EMPTY Consolidated Buffer"
#define LOGSTR_QUEING_EXCEPTION	"%s {pid:'%lu', o:'%p', cid:'%lu', queue_sz:'%lu', errno:'%d', error:'%s', e:'%d'}: QUEUEING IO EXCEPTION ERROR"
#define LOGSTR_IO_EXCEPTION "%s {pid:'%lu' o:'%p' cid:'%lu' errno:'%d' error:'%s', e:'%d'}: ERROR: NETWORK I/O: RETURNING"
#define LOGSTR_IO_READING_MSGQUE_BUF "%s {pid:'%lu', o:'%p', cid:'%lu', missing_msg_sz:'%lu', que_sz:'%lu', e:'%d'}: Reading/Decoding directly from SocketMessage buffer"
#define LOGSTR_IO_READ_MSGQUE_BUF_QUEEMPTY "%s {pid:'%lu', o:'%p', cid:'%lu', missing_msg_sz:'%lu', que_sz:'%lu', e:'%d'}: WARNING: COULD NOT READ SOCKETMESSAGE: NOT ENOUGH DATA"
#define LOGSTR_IO_READ_MSGQUE_NOTCONSOLIDATED	"%s {pid:'%lu', o:'%p', cid:'%lu', missing_msg_sz:'%lu', que_sz:'%lu', e:'%d'}: WARNING: MAY NOT HAVE SUFFICIENT DATA TO DECODE: IS QUEUE CONSOLIDATED?"
//not in use
//#define LOGSTR_IO_EXC_NOTOWNER	"%s {pid:'%lu', o:'%p', cid:'%lu', error:'%s', e:'%d'}: ERROR: NETWORK IO: DONT OWN SESSION: NOT SUSPENDING..."
#define LOGSTR_IO_BUF_CONSOLIDATED	"%s (pid:'%lu', o:'%p', cid='%lu', raw_msg_sz:'%lu', e:'%d'}: MESSAGE QUEUE: Entry consolidated into buffer"
#define LOGSTR_IO_BUF_CONSOLIDATED_FIN	"%s (pid:'%lu', o:'%p', cid='%lu', raw_msg_sz:'%lu', rcbytes:'%lu', blocksz:'%d', errno:'%d', e:'%d'}: Message Queue Consolidation: Ended: Fully consolidated queue into buffer"
#define LOGSTR_IO_BUF_CONSOLIDATED_PRE	"%s {pid:%lu, cid:'%lu', queue_sz:'%lu', raw_msg_sz:'%ld', rcbytes:'%lu', e:'%d}: Message Queue Consolidation: Started"
#define LOGSTR_IO_BUF_CONSOLIDATION_ERR	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'}: ERROR: SOCKET MESSAGE QUEUE COULD NOT BE CONSOLIDATED"
#define LOGSTR_IO_MSGQ_ADD_NODECODE	"%s {pid:'%lu', o:'%p', cid:'%lu', queue_sz:'%lu', raw_msg_sz:'%ld', missing_msg_sz:'%ld', rcbytes:'%lu', e:'%d'}: MESSAGE QUEUE: Added to queue without decoding"
#define LOGSTR_IO_INVALID_READ_FD	"%s {pid:'%lu', o:'%p', cid:'%lu', fd:'%d', missing_msg_sz:'%lu', raw_msg_sz:'%lu', holding_buffer_msg_sz:'%lu', suspended:'%d', e:'%d'): ! NOTICE: INVALID SOCKET FD READ"
#define LOGSTR_IO_RL_EXCEEDED_RATE_ACTIONS "%s (pid:'%lu', o:'%p', cid:'%lu', time:'%ld', actions:'%ld', e:'%d'): ERROR: RATELIMIT EXCEEDED FOR RATE AND NUMBER OF ACTIONS..."
#define LOGSTR_IO_RL_EXCEEDED_ACTIONS "%s (pid:'%lu', o:'%p', cid:'%lu', actions:'%ld', e:'%d'): ERROR: RATELIMIT EXCEEDED FOR NUMBER OF ACTIONS..."

#define LOGSTR_THREAD_RDLOCKTRY_FAIL "%s: {pid:'%lu', errno:'%d', error:'%s', e:'%d'): ERROR: COULD NOT ACQUIRE TRY-READ LOCK FOR '%s'"
#define LOGSTR_THREAD_RDLOCK_FAIL	 "%s: {pid:'%lu', errno:'%d', error:'%s', e:'%d'}: ERROR: COULD NOT ACQUIRE READ LOCK FOR '%s'"

#define LOGSTR_QUEDIOERR	"%s {pid:'%lu', o:'%p', cid:'%lu', errno:'%d', e:'%d'}: ERROR: DETECTED IN CONSOLIDATED QUEUE: '%s'"

#define LOGSTR_CACHE_SIZE	"%s {pid:'%lu', entries:'%lu', size='%lu', e:'%d'}: HashTable for: '%s'"
#define LOGSTR_CACH_INCONSIZE	"%s {pid:'%lu', loop_counter:'%d', stored_sessions:'%ld', e:'%d'}: ERROR: INCONSISTENT TABLE COUNT: LOOP COUNTER EXCEEDS STORED SESSIONS for: '%s'"
#define LOGSTR_CACHE_EXTRACTEDSET	"%s {pid:'%lu', extracted_set:'%d', e:'%d'}: EXCTRACTED SET FOR: '%s'"

#define LOGSTR_UFSRVWORKER_ONETHREADONLY	"%s {pid:'%lu', e:'%d'}: Work equest is already underway for: '%s'"
#define LOGSTR_TSWORKER_FAULTYSESN_OOB "%s {pid:'%lu' o:'%p' cid:'%lu' e:'%d'}: NOTICE: RECEIVED EVENT FOR FAULTY SESSION(OOB): IGNORING WORK REQUEST"
#define LOGSTR_TSWORKER_FAULTYSESN "%s {pid'%lu' o:'%p' cid='%lu' e:'%d'}: NOTICE: EVENT FOR FAULTY SESSION(LOCKED): IGNORING WORK REQUEST"
#define LOGSTR_TSWORKER_FAULTYSESN_COULDNTLOCK "%s {pid:'%lu' o:'%p' cid:'%lu' e:'%d'}: NOTICE: EVENT FOR FAULTY SESSION(COULDN'T LOCK): IGNORING WORK REQUEST"
#define LOGSTR_TSWORKER_POLLERR "%s {pid:'%lu' o:'%p' cid:'%lu' fd:'%d' e:'%d'}: ERROR: POLL EVENT (EPOLLRDHUP||EPOLLERR||EPOLLHUP): '%s'"
#define LOGSTR_TSWORKER_POLLERR_IN	"%s {pid:'%lu' o:'%p' cid:'%lu' fd:'%d' e:'%d'}: ERROR: POLL EVENT (EPOLLERR||EPOLLIN): '%s'"
#define LOGSTR_TSWORKER_HARD_SUSPEND	"%s {pid:%lu, o:'%p', cid'%lu', e:'%d'}: SESSION SUSPEND FLAG IS SET: PERFORMING HARD SUSPEND..."
#define LOGSTR_TSWORKER_WDP_MISSING_OBJ	"%s {pid:'%lu', o:'%p', cid='%lu', e:'%d'}: ERROR: COULD NOT GET THREAD-LOCAL Worker-DelegatorPipe SESSION."
#define LOGSTR_TSWORKER_WDP_BROEKN_WRITE	"%s {pid:'%lu', o:'%p', cid:'%lu', errno:'%d', e:'%d'}: ERROR WorkerDelegatorPipe: COULD NOT WRITE TO PIPE"
#define LOGSTR_TSWORKER_WDP_SUCCESS_WRITE	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'}: WorkerDelegatorPipe: Raised work recycle request.."
#define LOGSTR_TSWORKER_QUEUE_POST_REQUEST	"%s {pid:'%lu', o:'%p', cid:'%lu', queue_sz:'%lu', e:'%d}: SocketMessage Queue: New entries post request servicing: Raising recycle request"
#define LOGSTR_TSWORKER_BACKEND_INSTANTIATE	"%s {pid:'%lu', o:'%p', cid:'%lu', cid_backend:'%lu', e:'%d'): Instantiating from Backend: '%s'"

#define LOGSTR_WDELEG_NEWCONNECTION_ADDED	"%s {pid:'%lu', o:'%p', cid_new:'%lu', e:'%d'}: NEW CONNECTIONS QUEUE: FETCHED FROM CONNECTIONS QUEUE AND ADDEDD TO WORK QUEUE"
#define LOGSTR_WDELEG_WORKREQUEST_ADDED "%s {pid:'%lu', o:'%p', cid:'%lu', loop_counter:'%u', queue_sz:'%lu', e:'%d'}: WORK QUEUE: ADDED WORK REQUEST FOR EXISTING SESSION"
#define LOGSTR_WDELEG_NONCONNECTED_REQUEST	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'}: !WORK REQUET FOR NON_CONNECTED SESSION: IGNORING FROM QUEUE"
#define  LOGSTR_WDELEG_WORKER_REQUEST_RCV 	"%s (pid:'%lu', cid_pipe:'%lu', e:'%d'}: WorkerDelegatorPipe: Worker request received..."
#define LOGSTR_WDELEG_WORKERREAD_ERR	"%s {pid:'%lu', cid_pipe:'%lu', errno:'%d', rc:'%lu', e:'%d'}: ERROR WorkerDelegatorPipe: COULD NOT READ WORKER REQUEST"
#define LOGSTR_WDELEG_WORKERREAD_SUCCESS	"%s {pid:'%lu, cid_pipe:'%lu', cid_target:'%lu', rc:'%lu', e:'%d'}: WorkerDelegatorPipe: Processed recycle request for Session"
#define LOGSTR_WDELEG_WORKER_NULLREQUEST	"%s {pid:'%lu', cid_pipe:'%lu', e:'%d'}: !ERROR WorkerDelegatorPipe: COULDN'T IDENTIFY TARGET SESSION: RECEIVED NULL"
#define LOGSTR_WDELEG_EVENTS_POLLERROR	"%s {pid:'%lu' errno'%d' error'%s' e:'%d'}: !ERROR: EPOLL_WAIT: COULD NOT POLL I/O EVENTS"

#define LOGSTR_RECYCLER_ENQUE_REFCNT_SHORT	"%s {tail_pos:'%lu', refcount:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: NOTICE: REFCOUNT DID NOT REACH 1: COULD NOT ENQUEUE"
#define LOGSTR_RECYCLER_GET_FULLY_LEASED	"%s: {pid:'%lu' type_name:'%s, allocated_groups_sz:'%d', e:'%d'}: NOTICE: Type POOL FULLY LEASED: EXPAPD..."
#define LOGSTR_RECYCLER_PUT_ON_FULL	"%s {pid:'%lu', head_pos:'%lu', tail_pos:'%lu', type_name:'%s', leased_sz:'%lu' e:'%d'}: ERROR: POOL QUEUE WOULD OVER FLOW ON PUT REQUEST"
#define LOGSTR_RECYCLER_ENQUE_SUCCESS	"%s {pid:'%lu', groupid:'%u', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: Recycler: EnQueued item..."
#define LOGSTR_RECYCLER_DEQUE_SUCCESS	"%s {pid:'%lu', groupid:'%u', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: Recycler: DeQueued item..."
#define LOGSTR_RECYCLER_ENQUE_ERROR	"%s {pid:'%lu', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: ERROR: Recycler: COULD NOT ENQUEUE ELEMENT..."
#define LOGSTR_RECYCLER_DEQUE_ERROR	"%s {pid:'%lu', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: ERROR: Recycler: COULD NOT DEQUEUE ELEMENT..."
#define LOGSTR_RECYCLER_QUEUE_ITEM_REFCOUNT_ERROR	"%s {pid:'%lu', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', refcount:'%lu', type_name:'%s, leased_sz:'%lu', e:'%d'}: ERROR: QUEUE ITEM HAS UNEXPECTED REFCOUNT: '%s'"
#define LOGSTR_RECEYCLER_ALLOC_GROUP_IDX_ERR	"%s {pid:'%lu, rid:'%lu', pool_sz:'%u', allocation_group_idx:'%lu', e:'%d'}: ERROR: COULD NOT RETRIEVE AllocationGroup index..."
#define LOGSTR_RECYCLER_MAX_ALLOC_CAPACITY_REACHED "%s {pid:'%lu' allocated_groups:'%d' expansion_size:'%u', e:'%d'}: REACHED MAXIMUM ALLOCATION CAPACITY..."
#define LOGSTR_RECYCLER_ALLOC_GROUP_EXPANDED	"%s {type_name:'%s', groupid:'%u', head_pos:'%lu', tail_pos:'%lu', queue_alloc_sz:'%d', block_sz:'%lu', alloc_groups_sz:'%d', max_capacity:'%lu', e:'%d'}: AllocationGroup Expanded..."
#define LOGSTR_RECYCLER_UNCOLLECTED_INSTANCE "%s pid:'%lu', groupid:'%u', tail_pos:'%lu', head_pos:'%lu', o:'%p', rid:'%lu', type_name:'%s, leased_sz:'%lu', instances_sz:'%lu', e:'%d'}: ERROR: UNCOLLECTED INSTANCES FOUND: SHOULD MAX OF 1"
#define LOGSTR_RECYCLER_INSTANCE_NOT_ON_LIST "%s pid:'%lu', env:'%p', o:'%p', e:'%d'}: ERROR: INSTANCE NOT FOUND ON OWN TYPE INSTANCES LIST"
#define LOGSTR_RECYCLER_MARSHALLER_INSTANCE "%s pid:'%lu', o:'%p', marshaller_id:'%lu', e:'%d'}: ERROR: INSTANCE IS IN MARSHALLER STATE"
#define LOGSTR_RECYCLER_NEW_INSTANCE_ERROR	"%s: {pid:'%lu' o:'%p, e:'%d'}: ERROR: COULD NOT CREATE NEW INSTANCE HOLDER"

#define LOGSTR_SESSION_SUCCESS_MIGRATED	"%s {pid:'%lu', o:'%p', o_migrated:'%p', cid_migrated:'%lu', e:'%d'}: Session was migrated from another server..."
#define LOGSTR_SESSION_ERROR_MIGRATED "%s {pid:'%lu' o:'%p', cid:'%lu',e:'%d'}: ERROR: COULD NOT INSTANTIATE MIGRATED SESSION "
#define LOGSTR_ACCOUNT_INVALID_SIGNON_COOKIE	"%s {pid:'%lu', o:'%p', cid:'%lu', cookie:'%s', e:'%d'}: COULD NOT VALIDATE SignOn Cookie"
#define LOGSTR_SESSION_SUCCESS_REFRESHED_BKEND "%s {pid:'%lu', o:'%p', cid:'%lu', o_refreshed:'%p', cid_refreshed:'%lu', uid_refreshed:'%lu', e:'%d'}: Refreshed Session from Backend..."
#define LOGSTR_SESSION_ERROR_REFRESHED_BKEND "%s {pid:'%lu', o:'%p', cid:'%lu', cid_to_refresh:'%lu', id_to_refresh:'%lu', e:'%d'}: ERROR: SESSION COULD NOT BE REFRESHED FROM BACKEND: LETTING USER THROUGH WITH FERSH INITIALISATION"
#define LOGSTR_SESSION_NOTONLINE_INITIALISING	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'}: COULD NOT LOCATE USER ONLINE: Proceeding with Session initialisation..."
#define LOGSTR_SESSION_DISTRIBUTED_ID_GENERATED	"%s {timestamp:'%lu', shard_id:'%lu', seq_id:'%lu', id:'%lu', e:'%d'}: Generated distributed id..."
#define LOGSTR_SESSION_MISSING_FENCE "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', e:'%d'}: ERROR: DATA INTEGRITY: USER IS PRESENT IN FENCE SESSION LIST WITH NO FENCE REFERENCE IN USER SESSION..."
#define LOGSTR_SESSION_EVENET_ID_ERROR_BACKEND	"%s {pid:'%lu', o:'%p', cid:'%lu', eid:'%lu', e:'%d'}: ERROR: BACKEND COULD NOT GENERATE SESSION EVENT ID"

#define LOGSTR_BACKENDCACHE_ERROR_REPLYOBJECT	"%s {pid:'%lu', o:'%p', query:'%s', e:'%d'}: ERROR: NULL REDIS REPLY OBJECT"
#define LOGSTR_BACKENDCACHE_ERROR_REPLYTYPE	"%s {pid:'%lu', o:'%p', query:'%s', returned_type:'%d', e:'%d'}: ERROR: Backend Cache: '%s'"
#define LOGSTR_BACKENDCACHE_NILL_REPLY	"%s {pid:'%lu', o:'%p', query:'%s', returned_type:'%d', e:'%d'}: Backend Cache: Empty Reply Set:  '%s'"
#define LOGSTR_BACKENDCACHE_UNSPECIFIED_REPLY	"%s {pid:'%lu', o:'%p', query:'%s', returned_type:'%d', e:'%d'}: Backend Cache: '%s'"
#define LOGSTR_BACKENDCACHE_REPLY	"%s {pid:'%lu', o:'%p', query_result:'%s', e:'%d'}: Backend Cache: '%s'"
#define LOGSTR_BACKENDCACHE_SHARED_CONTACTS	"%s {pid:'%lu', o:'%p' idx:'%d', token:'%s', e:'%d'}: Backend Cache: '%s'"
#define LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT	"%s {pid:'%lu', o:'%p' found:'%d', e:'%d'}: Backend Cache: '%s'"

#define LOGSTR_BACKENDDB_QUERY_STRING	"%s {pid:'%lu', o:'%p', query:'%s', e:%d'}: Query: Generated Query string..."
#define LOGSTR_BACKENDDB_CONNECTION_ERROR "%s (pid:'%lu', o:'%p', cid='%lu', query:'%s', e:'%d'}: ERROR: QUERY: COULD NOT EXECUTE"
#define LOGSTR_BACKENDDB_EMPTY_RESULTSET "%s (pid:'%lu', o:'%p', cid='%lu', query:'%s', e:'%d'}: Query: Zero result-set returned"

#define LOGSTR_ACCOUNT_VERIFICATION_CODE_MISMATCH	"%s {pid:'%lu', o:'%p', cid:'%lu', stored:'%d', supplied:'%lu', e:'%d'}: VERIFICATION CODES DID NOT MATCH"
#define LOGSTR_ACCOUNT_ATTCH_PATH_INVALID "%s {pid:'%lu', o:'%p', stored_path:'%s' user_path:'%s', e:'%d'}: ERROR: INCONSISTENT ATTACHEMENT PATH..."
#define LOGCSTR_ACCOUNT_ATTCH_NO_MATCH	"%s {pid:'%lu', o:'%p', stored_path:'%s' user_path:'%s', e:'%d'}: ERROR: SUPPLIED ATTACHEMENT PATH DOES NOT MATCH STOTRED..."
#define LOGCSTR_ACCOUNT_ATTCH_NO_REQUEST_NONCE	"%s {pid:'%lu', o'%p', attachment_id:'%s', e:'%d'}: ERROR: ATTCHMENT NONCE MISSING FROM REQUEST HEADER"
#define LOGSTR_ACCOUNT_ATTCH_DOWNLOADED_SUCCESS "%s {pid:'%lu', o:'%p', file_location:'%s', e:'%d'}: Attachment downloaded..."
#define LOGSTR_ACCOUNT_IDKEY_ERROR	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'): ERROR: '%s'"
#define LOGSTR_ACCOUNT_SIGNED_PREKEY_ERROR	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'): ERROR: '%s'"
#define LOGSTR_ACCOUNT_PREKEY_ERROR	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'): ERROR: '%s'"
#define LOGSTR_ACCOUNT_LASTRESORTKEY_ERROR	"%s {pid:'%lu', o:'%p', cid:'%lu', e:'%d'): ERROR: '%s'"

#define LOGSTR_PROTO_COMMAND_ENVELOPE_MISSING	"%s: {pid:'%lu' o:'%p', uname:'%s', offset:'%'u', e:'%d'}: Received empty command envelope"
#define LOGSTR_PROTO_COMMAND_MISSING	"%s: {pid:'%lu' o:'%p', uname:'%s', e:'%d'}: Received empty command"
#define LOGSTR_PROTO_COMMAND_FOUND	"%s: {pid:'%lu', o:'%p', uname:'%s', path:'%s', cmd_idx:'%d', command:'%s', id:'%lu', e:'%d'}: Retrieved Command Index: Invoking callback"
#define LOGSTR_PROTO_COMMAND_TYPE_ERROR	"%s: {pid:'%lu', o:'%p', uname:'%s', command:'%s', req_type:'%d', e:'%d'}: Received unknown WebSocket Request type"
#define LOGSTR_PROTO_COMMAND_UNPACK_ERROR	"%s: {pid:'%lu', o:'%p', uname:'%s', frame_offset:'%d', payload_len:'%lu', e:'%d'}: ERROR: COULD NOT UNPACK WebSocketMessage structure..."

#define LOGSTR_FENCE_EVENET_ID_ERROR_BACKEND	"%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', eid:'%lu', e:'%d'}: ERROR: BACKEND COULD NOT GENERATE FENCE EVENT ID"
#define LOGSTR_FENCE_BACKEND_USERLIST_MISMATCH "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu', fence_members_sz:'%d', e:'%d'}: CRITICAL ERROR: COULD NOT LOAD FENCE'S SESSION LIST FROM BACKEND: BUT LOCAL FENCE'S LIST IS NOT ZERO"
#define LOGSTR_FENCE_MISSING_SESSION "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', e:'%d'}: ERROR: DATA INTEGRITY: FENCE IS PRESENT IN USER SESSION LIST WITH NO SESSION REFERENCE IN FENCE's SESSION LIST..."
#endif /* SRC_INCLUDE_LOG_MESSAGE_LITERALS_H_ */
