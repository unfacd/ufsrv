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
#include <misc.h>
#include <thread_context_type.h>
#include <utils.h>
#include <utils_crypto.h>
#include <ufsrv_core/user/users.h>
#include <session_service.h>
#include <session.h>
#include <ufsrvuid.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_core/user/user_backend.h>
#include <uflib/db/db_sql.h>
#include <sessions_delegator_type.h>
#include <recycler/recycler.h>
#include <attachments.h>
#include <adt_locking_lru.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;
extern ufsrv *const masterptr;

static HashTable 		AttachmentsHashTable;
static LockingLru 	AttachmentsLruCache;

//type recycler pool for AttachmentDescriptor
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//assigned when the typepool is initialised
static RecyclerPoolHandle *AttachmentDescriptorPoolHandle;

static int	TypePoolInitCallback_AttachmentDescriptor (ClientContextData *data_ptr, size_t oid);
static int	TypePoolGetInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int	TypePoolPutInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char	*TypePoolPrintCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int	TypePoolDestructCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static ClientContextData *_ExtractAttachmentDescriptor (ClientContextData *item_ptr);

static char *_PrintAttachment (ClientContextData *item_ptr, size_t index);

static RecyclerPoolOps ops_attachment_descriptor ={
		TypePoolInitCallback_AttachmentDescriptor,
		TypePoolGetInitCallback_AttachmentDescriptor,
		TypePoolPutInitCallback_AttachmentDescriptor,
		TypePoolPrintCallback_AttachmentDescriptor,
		TypePoolDestructCallback_AttachmentDescriptor
};
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

static UFSRVResult *_DbInsertNewAttachment (AttachmentDescriptor *attachment_ptr, unsigned long userid, unsigned long fid, unsigned device_id);
inline static void _InitialiseAttachmentsHashTable (HashTable *attachments_hashtable_ptr, size_t, unsigned long call_flags);

static InstanceHolderForAttachmentDescriptor  * _CacheLocalLruGetAttachment (Session *sesn_ptr, const char *blob_id);
static InstanceHolderForAttachmentDescriptor * _CacheLocalLruSetAttachmentItem (Session *sesn_ptr, InstanceHolderForAttachmentDescriptor *instance_attachment_ptr_in);


/**
 * 	@brief: For proto_http
 */
void
InitialiseAttachmentsHashTable ()
{
	InitLockingLruItemRecyclerTypePool (); //this only executes once per server instance
	InitLockingLru (&AttachmentsLruCache, "Attachments", _CONFIDEFAULT_HASHTABLE_ATTACHMENTS_SZ, &AttachmentsHashTable, _InitialiseAttachmentsHashTable, (ItemExtractor)_ExtractAttachmentDescriptor, (ItemPrinter)_PrintAttachment);
}

/**
 * @brief Since AttachmentDescriptors are instantiated from the recycler, the hastable stores InstanceHolder types for AttachmentDescriptor
 */
inline static void
_InitialiseAttachmentsHashTable (HashTable *hashtable_ptr, size_t max_size, unsigned long call_flags)
{
	if (HashTableLockingInstantiate(hashtable_ptr, (offsetof(AttachmentDescriptor, id)), KEY_SIZE_ZERO, HASH_ITEM_NOT_PTR_TYPE, "Attachments", (ItemExtractor)_ExtractAttachmentDescriptor)) {
		HASHTABLE_CLEARFLAG(&AttachmentsHashTable, flag_resizable);
		hashtable_ptr->max_size = max_size;
		syslog(LOG_INFO, "%s: SUCCESS: Attachments HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'. max_size:'%lu'", __func__, hashtable_ptr->fKeyOffset, hashtable_ptr->fKeySize, hashtable_ptr->max_size);
	} else {
		syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE Attachments HashTable: TERMINATING...", __func__, errno);

		exit(-1);
	}
}

//DB OPS

/**
 * 	@brief: Frontend function for storing attachments into the DbBackend with the option of lru layer. A valid blob id is necessary, which requires the asset
 * 	to be successfully loaded first. If it is in the DbBackend then it is in the FS somewhere.
 * 	@param cache_it: only supported with ufsrvapi instance
 */
UFSRVResult *
DbAttachmentStore (Session *sesn_ptr,  AttachmentDescriptor *attachment_ptr, unsigned long fid, unsigned device_id)
{
	_DbInsertNewAttachment(attachment_ptr, UfsrvUidGetSequenceId(&(SESSION_UFSRVUIDSTORE(sesn_ptr))), fid, device_id);

  _RETURN_RESULT_SESN(sesn_ptr, THREAD_CONTEXT_UFSRV_RESULT_USERDATA, THREAD_CONTEXT_UFSRV_RESULT_TYPE_, THREAD_CONTEXT_UFSRV_RESULT_CODE_)
}

static UFSRVResult *
_DbInsertNewAttachment (AttachmentDescriptor *attachment_ptr, unsigned long userid, unsigned long fid, unsigned device_id)
{
#define SQL_INSERT_ATTACHMENT "INSERT INTO attachments (blob_id, `key`, digest, blurhash, caption, mimetype, key_size, digest_size, size, fid, userid, device_id, id_events) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%lu', '%lu', '%lu', '%lu', '%lu', '%d', '%lu') "

  char *sql_query_str = mdsprintf(SQL_INSERT_ATTACHMENT, attachment_ptr->id, attachment_ptr->key_encoded, attachment_ptr->digest_encoded, IS_STR_LOADED(attachment_ptr->blurhash)?attachment_ptr->blurhash:NULL, IS_STR_LOADED(attachment_ptr->caption)?attachment_ptr->caption:NULL, attachment_ptr->mime_type, attachment_ptr->key_sz, attachment_ptr->digest_sz, attachment_ptr->size, fid, userid, device_id, attachment_ptr->eid);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif

	int sql_result = h_query_insert(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
	}

  free (sql_query_str);

  struct _h_data *db_data = h_query_last_insert_id(THREAD_CONTEXT_DB_BACKEND);
  if (db_data->type == HOEL_COL_TYPE_INT) {
    int last_id = ((struct _h_type_int *) db_data->t_data)->value;
    h_clean_data_full(db_data);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *) (uintptr_t) last_id, RESCODE_BACKEND_DATA)
  }

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)

#undef SQL_INSERT_ATTACHMENT
}

int
DbAttachmentDelete (Session *sesn_ptr, const char *attachment_id)
{
//if number alreaduy has a code, overwrite it...
#define SQL_DELETE_ATTACHMENT "DELETE FROM attachments WHERE blob_id='%s'"

	char *sql_query_str;
	sql_query_str = mdsprintf(SQL_DELETE_ATTACHMENT, attachment_id);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result = h_query_delete(sesn_ptr->db_backend, sql_query_str);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
    free (sql_query_str);

		return H_ERROR;
	}

  free (sql_query_str);

	return sql_result;

#undef SQL_DELETE_ATTACHMENT
}

/**
 * 	@brief:
 * 	@ALERT: This function will use standard malloc if attachment_ptr_in * was NULL. To use TypePool, make sure you
 * 	pass in an instance that was instantiated through the TypePool
 * 	@dynamic_memory AttachmentDescriptor *: EXPORTS if attachment_ptr_out was null
 */
UFSRVResult *
DbGetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attachment_ptr_out)
{
	//IMPORTNT TINYTEXT is returned as blob, not text
#define SQL_SELECT_ATTACHMENT_DOWNLOAD 	"SELECT mimetype, size, `key`, key_size, digest, digest_size, id_events, blurhash, caption FROM attachments WHERE blob_id = '%s';"
#define QUERY_RESULT_MIMETYPE(x)				((struct _h_type_blob *)result.data[x][0].t_data)->value
#define QUERY_RESULT_MIMETYPE_LEN(x)		((struct _h_type_blob *)result.data[x][0].t_data)->length
#define QUERY_RESULT_SIZE(x)						((struct _h_type_int *)	result.data[x][1].t_data)->value
#define QUERY_RESULT_KEY(x)							((struct _h_type_blob *)result.data[x][2].t_data)->value
#define QUERY_RESULT_KEY_LEN(x)					((struct _h_type_blob *)result.data[x][2].t_data)->length
#define QUERY_RESULT_KEYSIZE(x)					((struct _h_type_int *)	result.data[x][3].t_data)->value
#define QUERY_RESULT_DIGEST(x)					((struct _h_type_blob *)result.data[x][4].t_data)->value
#define QUERY_RESULT_DIGEST_LEN(x)			((struct _h_type_blob *)result.data[x][4].t_data)->length
#define QUERY_RESULT_DIGESTSIZE(x)			((struct _h_type_int *)	result.data[x][5].t_data)->value
#define QUERY_RESULT_EVENTS_ID(x)			  ((struct _h_type_int *)	result.data[x][6].t_data)->value
#define QUERY_RESULT_BLURHASH(x)				((struct _h_type_blob *)result.data[x][7].t_data)->value
#define QUERY_RESULT_BLURHASH_LEN(x)		((struct _h_type_blob *)result.data[x][7].t_data)->length
#define QUERY_RESULT_CAPTION(x)				  ((struct _h_type_blob *)result.data[x][8].t_data)->value
#define QUERY_RESULT_CAPTION_LEN(x)		  ((struct _h_type_blob *)result.data[x][8].t_data)->length
#define QUERY_RESULT_DIGEST_NOTNULL(x)	(IS_PRESENT((struct _h_type_blob *)result.data[x][4].t_data) && IS_PRESENT((struct _h_type_blob *)result.data[x][5].t_data))
#define QUERY_RESULT_BLURHASH_NOTNULL(x)	(IS_PRESENT((struct _h_type_blob *)result.data[x][7].t_data))
#define QUERY_RESULT_CAPTION_NOTNULL(x)	  (IS_PRESENT((struct _h_type_blob *)result.data[x][8].t_data))


	int 		rescode;
	char 		*sql_query_str;
	struct 	_h_result result;

	sql_query_str = mdsprintf(SQL_SELECT_ATTACHMENT_DOWNLOAD, blob_id);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK)		goto return_db_error;
	if (result.nb_rows == 0)	goto return_db_emptyset;

	AttachmentDescriptor *attachment_ptr = NULL;

	if (IS_EMPTY(attachment_ptr_out))	attachment_ptr = calloc(1, sizeof(AttachmentDescriptor));
	else															attachment_ptr = attachment_ptr_out;

	attachment_ptr->size = QUERY_RESULT_SIZE(0);
	strncpy(attachment_ptr->mime_type, QUERY_RESULT_MIMETYPE(0), (QUERY_RESULT_MIMETYPE_LEN(0)>SBUF-1?SBUF-1:QUERY_RESULT_MIMETYPE_LEN(0)));
	if (flag_fully_populate) {
		strncpy(attachment_ptr->id, blob_id, MBUF - 1);
		if (QUERY_RESULT_KEY_LEN(0) > 0) {
			//TODO: b64-encoded key would hold more than the original key size, so theoretically assuming key can have max of MBUF bytes,
			//for encoded keys hitting the extreme end it will be truncated. But reality key sizes are smaller than the generous MBUF, so we should be fine
			attachment_ptr->key_encoded = strndup(QUERY_RESULT_KEY(0), (QUERY_RESULT_KEY_LEN(0)>MBUF-1?MBUF-1:QUERY_RESULT_KEY_LEN(0)));
			attachment_ptr->key_sz			=	QUERY_RESULT_KEYSIZE(0);
		}

		//todo: QUERY_RESULT_DIGEST_NOTNULL() is temporary should be removed once data is cleansed
		if (QUERY_RESULT_DIGEST_NOTNULL(0) && QUERY_RESULT_DIGEST_LEN(0) > 0) {
			//TODO: b64-encoded digesr would hold more than the original key size, so theoretically assuming key can have max of MBUF bytes,
			//for encoded keys hitting the extreme end it will be truncated. But reality key sizes are smaller than the generous MBUF, so we should be fine
			attachment_ptr->digest_encoded  = strndup(QUERY_RESULT_DIGEST(0), (QUERY_RESULT_DIGEST_LEN(0)>MBUF-1?MBUF-1:QUERY_RESULT_DIGEST_LEN(0)));
			attachment_ptr->digest_sz			  =	QUERY_RESULT_DIGESTSIZE(0);
		}

		if (QUERY_RESULT_BLURHASH_NOTNULL(0)) {
      attachment_ptr->blurhash = strndup(QUERY_RESULT_BLURHASH(0), QUERY_RESULT_BLURHASH_LEN(0));
		}

    if (QUERY_RESULT_CAPTION_NOTNULL(0)) {
      attachment_ptr->caption = strndup(QUERY_RESULT_CAPTION(0), QUERY_RESULT_CAPTION_LEN(0));
    }

		//todo: other fields
	}

	return_success:
	free (sql_query_str);
	h_clean_result(&result);
	_RETURN_RESULT_SESN(sesn_ptr, (void *)attachment_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);


	return_db_error:
	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);
	rescode = RESCODE_BACKEND_CONNECTION;
	goto final_cleanout;

	return_db_emptyset:
	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);
	rescode = RESCODE_BACKEND_DATA_EMPTYSET;
	h_clean_result(&result);
	goto final_cleanout;

	final_cleanout:
	free (sql_query_str);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

#undef SQL_SELECT_ATTACHMENT_DOWNLOAD
#undef QUERY_RESULT_MIMETYPE
#undef QUERY_RESULT_SIZE

}

//DB OPS

void
AttachmentDescriptorDestruct (AttachmentDescriptor *attachment_ptr, bool deallocate_encoded, bool self_destruct)
{
	if (unlikely(IS_EMPTY(attachment_ptr)))	return;

	if (deallocate_encoded) {
		if (!IS_EMPTY(attachment_ptr->key_encoded))			free (attachment_ptr->key_encoded);
		if (!IS_EMPTY(attachment_ptr->digest_encoded))	free (attachment_ptr->digest_encoded);
	}

	if (IS_PRESENT(attachment_ptr->thumbnail))				free (attachment_ptr->thumbnail);
  if (IS_PRESENT(attachment_ptr->blurhash))				free (attachment_ptr->blurhash);
  if (IS_PRESENT(attachment_ptr->caption))				  free (attachment_ptr->caption);

	memset (attachment_ptr, 0, sizeof(AttachmentDescriptor));

	if (self_destruct)	{free (attachment_ptr); attachment_ptr = NULL;}

}

/**
 * 	@brief: Queries existing stores for the existence of an attachment based on its id. This is a lookup function.
 *  @warning: this ufsrvapi function as it utilises lru
 * 	@param promote: if flagged false performs lookup without teh side effect of promoting the cache
 * 	@return extracted and offset item from LRU cache
 * 	@dynamic_memory: EXPORTS INSTANCE FROM POOL
 */
AttachmentDescriptor *
GetAttachmentDescriptor (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate)
{
	if (unlikely(!IS_STR_LOADED(blob_id)))	return NULL;

	InstanceHolderForAttachmentDescriptor *instance_attachment_ptr = _CacheLocalLruGetAttachment (sesn_ptr, blob_id);
	if (IS_PRESENT(instance_attachment_ptr))	return _ExtractAttachmentDescriptor(instance_attachment_ptr);

	instance_attachment_ptr = AttachmentDescriptorGetInstance(NULL, CALLFLAGS_EMPTY);
	if (unlikely(IS_EMPTY(instance_attachment_ptr)))	return NULL;

  AttachmentDescriptor *attachment_ptr_unoffset = AttachmentDescriptorOffInstanceHolder(instance_attachment_ptr);

	uintptr_t p = (uintptr_t)attachment_ptr_unoffset;
  AttachmentDescriptor *attachment_ptr = (AttachmentDescriptor *)(p + (sizeof(uintptr_t)));

	DbGetAttachmentDescriptor (sesn_ptr, blob_id, flag_fully_populate, attachment_ptr);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		_exit_success:
		_CacheLocalLruSetAttachmentItem (sesn_ptr,  instance_attachment_ptr);

		return _ExtractAttachmentDescriptor(instance_attachment_ptr);
	}

	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', blob_id:'%s'}: Could not instantiate AttachmentDescriptor: Returning to TypePool...", __func__, pthread_self(), sesn_ptr, blob_id);

	AttachmentDescriptorReturnToRecycler (instance_attachment_ptr, NULL, CALLFLAGS_EMPTY);

	return NULL;

}

//START LRU STUFF....

/**
 * 	@brief:	Basic interface for querying the local LruCache for the existence of a given attachment descriptor.
 */
static InstanceHolderForAttachmentDescriptor  *
_CacheLocalLruGetAttachment (Session *sesn_ptr, const char *blob_id)
{
	InstanceHolderForAttachmentDescriptor *instance_attachment_ptr,
											                  *instance_attachment_ptr_evicted = NULL;

  instance_attachment_ptr = (InstanceHolderForAttachmentDescriptor *)LockingLruGet (&AttachmentsLruCache, sesn_ptr, blob_id, (LruClientData **)&instance_attachment_ptr_evicted);

	return instance_attachment_ptr;

}

/**
 * 	@brief: Basic interface function for caching AttachmentDescriptors
 * 	We leave an extra room for a hidden reference to the Lrus list item at the beginning of the block,  corresponding with
 * 	this AttachmentDescriptor so we can derive them from
 * 	one another.
 *
 * 	@param attachment_ptr_in: must be an un-offset reference
 */
static InstanceHolderForAttachmentDescriptor *
_CacheLocalLruSetAttachmentItem (Session *sesn_ptr,  InstanceHolderForAttachmentDescriptor *instance_attachment_ptr_in)
{
	uintptr_t p;
	AttachmentDescriptor *attachment_ptr_unoffset = AttachmentDescriptorOffInstanceHolder(instance_attachment_ptr_in);
	AttachmentDescriptor *evicted_item_ptr = NULL;

	p = (uintptr_t)attachment_ptr_unoffset;

	__unused AttachmentDescriptor *attachment_ptr = (AttachmentDescriptor *)(p + (sizeof(uintptr_t)));

	LruClientData *data_ptr_returned = LockingLruSet (&AttachmentsLruCache, sesn_ptr, (LruClientData *)instance_attachment_ptr_in);
	if (IS_PRESENT(data_ptr_returned))	{
	  assert (data_ptr_returned == instance_attachment_ptr_in);
    return instance_attachment_ptr_in;
	}

	return NULL;

}

//END LRU

/**
 * 	@brief: retrieve descriptor based on provided id. Designed to be used with ufsrv and therefore bypasses the lru stuff
 */
//AttachmentDescriptor *
//GetAttachmentDescriptorEphemeral (Session *sesn_ptr, const char *blob_id, AttachmentDescriptor *attch_ptr_out)
//{
//	if (unlikely(IS_EMPTY(blob_id)))	return NULL;
//
//	AttachmentDescriptor *attch_ptr	=	NULL;
//	if (IS_PRESENT(attch_ptr_out))	attch_ptr=attch_ptr_out;
//	else														attch_ptr=calloc(1, sizeof(AttachmentDescriptor));
//
//	DbGetAttachmentDescriptor (sesn_ptr, blob_id, attch_ptr, false);
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//		return_success:
//
//		return attch_ptr;
//	}
//
//	return NULL;
//
//}



//----------- Recycer Type Pool Attachment ---- //

void InitAttachmentDescriptorRecyclerTypePool ()
{
	#define _THIS_EXPANSION_THRESHOLD (1024*100)
	//IMPORTANT: note 'sizeof(AttachmentDescriptor)+sizeof(uintptr_t)' as Attachment is Lru-managed which needs an extra offset
	AttachmentDescriptorPoolHandle = RecyclerInitTypePool("AttachmentDescriptor",
                                                        sizeof(AttachmentDescriptor) + sizeof(uintptr_t), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                                        _THIS_EXPANSION_THRESHOLD, &ops_attachment_descriptor);

	syslog(LOG_INFO, "%s: Initialised TypePool (WITH EXTRA uintptr_t offset for LRU): '%s'. TypeNumber:'%d', Block Size:'%lu'", __func__, AttachmentDescriptorPoolHandle->type_name, AttachmentDescriptorPoolHandle->type, AttachmentDescriptorPoolHandle->blocksz);
}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime. No InstanceHolder ref yet.
 *
 */
static int
TypePoolInitCallback_AttachmentDescriptor (ClientContextData *data_ptr, size_t oid)
{
	AttachmentDescriptor *descriptor_ptr = (AttachmentDescriptor *)data_ptr;

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Get().
 */
static int
TypePoolGetInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Put In this instance Fence *
 */
static int
TypePoolPutInitCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

	AttachmentDescriptorDestruct(descriptor_ptr, true, false);

	return 0;//success
}

static char *
TypePoolPrintCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

	return NULL;
}

static int
TypePoolDestructCallback_AttachmentDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  AttachmentDescriptor *descriptor_ptr = AttachmentDescriptorOffInstanceHolder((InstanceHolderForAttachmentDescriptor *)data_ptr);

	return 0;//success

}

void
AttachmentDescriptorIncrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples)
{
	RecyclerTypeReferenced (AttachmentDescriptorPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
AttachmentDescriptorDecrementReference (InstanceHolderForAttachmentDescriptor *instance_descriptor_ptr, int multiples)
{
	RecyclerTypeUnReferenced (AttachmentDescriptorPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

unsigned
AttachmentDescriptorPoolTypeNumber()
{
	unsigned  type = AttachmentDescriptorPoolHandle->type;
	return type;
}

InstanceHolderForAttachmentDescriptor *
AttachmentDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags)
{
	InstanceHolder *instance_holder_ptr = RecyclerGet(AttachmentDescriptorPoolTypeNumber(), ctx_data_ptr, call_flags);
	if (unlikely(IS_EMPTY(instance_holder_ptr)))	goto return_error;

	return instance_holder_ptr;

	return_error:
	syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), (void *)0, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get AttachmentDescriptor instance");
	return NULL;

}

void
AttachmentDescriptorReturnToRecycler (InstanceHolderForAttachmentDescriptor *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
	RecyclerPut(AttachmentDescriptorPoolTypeNumber(), instance_holder_ptr, (ContextData *)ctx_data_ptr, call_flags);
}

/**
 * @brief Since the AttachmentDescriptor is allocated with extra 8-byte and offset by the same amount, this special
 * extractor is needed to retrieve actual data object. See @InitAttachmentDescriptorRecyclerTypePool
 * @param item_ptr Object previously allocated by Recycler.
 * @return pointer at data payload point, which lru cache system can offset (back) to obtain LruItem
 */
static ClientContextData *
_ExtractAttachmentDescriptor (ClientContextData *item_ptr)
{
  AttachmentDescriptor *attachment_ptr_unoffset = AttachmentDescriptorOffInstanceHolder(item_ptr);
  uintptr_t p = (uintptr_t)attachment_ptr_unoffset;

  return (ClientContextData *)(p + (sizeof(uintptr_t)));

}

/**
 * @brief Default item printer for AttachmentDescriptor LRU items
 * @param item_ptr Aliased and un-extracted AttachmentDescriptor
 * @param index item iterator index position
 * @return
 */
static char *
_PrintAttachment (ClientContextData *item_ptr, size_t index)
{
  AttachmentDescriptor *attachment_ptr = _ExtractAttachmentDescriptor(item_ptr);
  syslog(LOG_ERR, "%s (pid:'%lu', attachment_id:'%s', idx:'%lu'): ListItem Client Data", __func__, pthread_self(), attachment_ptr->id, index);

  return NULL;

}
////end typePool  /////////////////////
