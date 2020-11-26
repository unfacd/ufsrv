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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <nportredird.h>
#include <misc.h>
#include <utils.h>
#include <utils_crypto.h>
#include <ufsrv_core/user/users.h>
#include <session.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_core/user/user_backend.h>
#include <protocol_http_attachments.h>

extern ufsrv *const masterptr;

static char *_AttachmentPathGenerate (void);

#include <utils_nonce.h>
/**
 * 	@brief: Generate a temporary context to accept a network file upload. The system generates a random nonce and a random path
 * 	which have limited TTL. The user must supply both in order for the upload to be accepted.
 * 	A hash in the backend "_ATTACHEMENT:<nonce> <path> is set which is to be referenced back when user sends a request for uplaod.
 * 	The DbBackend is only stroed into upon successful upload.
 *
 * 	@dynamic_memory:	Allocates 'AttachmentDescription *' which user must free withAttachementDescriptionDestruct()
 */
AttachmentDescription *
BackendAttachmentGenerate (Session *sesn_ptr)
{
	char *attachment_path = _AttachmentPathGenerate();
	if (attachment_path) {
		char *attachment_nonce = BackEndGenerateNonce(sesn_ptr, _CONFIGDEFAULT_ATTACHMENT_NONCE_EXPIRY, "_ATTACHMENT", attachment_path);

		if (unlikely(IS_EMPTY(attachment_nonce))) {
			free (attachment_path);
			return NULL;
		}

		AttachmentDescription *attch_ptr = calloc(1, sizeof(AttachmentDescription));
		attch_ptr->nonce = attachment_nonce;
		attch_ptr->path = attachment_path;

		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', attachment_path:'%s', nonce:'%s'}: Attachment: Generated description...", __func__, pthread_self(), sesn_ptr, attachment_path, attachment_nonce);

		return attch_ptr;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s'}: ERROR: COULD NOT GENERATE Attachment path...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr));
	}

	return NULL;

}

void
AttachementDescriptionDestruct (AttachmentDescription *attch_ptr, bool self_destruct)
{
	if(unlikely(attch_ptr==NULL))	return;

	if(attch_ptr->nonce)	free(attch_ptr->nonce);
	if(attch_ptr->path)	free(attch_ptr->path);

	if (self_destruct)	{free (attch_ptr);	attch_ptr=NULL;}

}

static char *_AttachmentPathGenerate (void)
{
//#define _UPLOAD_SERVER_NAME "https://api.unfacd.io:20080/"
	char *random_path=(char *)GenerateSalt (64, true/*zero terminated*/);
	if (random_path)
	{
		char *attachment_path=NULL;
		asprintf(&attachment_path, "%sV1/Account/Attachment/%s", masterptr->ufsrvmedia_upload_uri, random_path);

		return attachment_path;
	}

	return NULL;
}

/**
 * @brief: for successfully uploaded attachment, store a permanent reference to its location for future download requests.
 * This is a permenant hash. The id cannot change, but location can, which is what is returned back to the user.
 */
UFSRVResult *
BackendAttachmentStoreLocationId (Session *sesn_ptr_carrier, const char *id, const char *location)
{
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr;

	if (unlikely((IS_EMPTY(id)) || (IS_EMPTY(location)))) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "id or location");

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	pers_ptr = sesn_ptr_carrier->persistance_backend;

	redis_ptr = (*pers_ptr->send_command)(sesn_ptr_carrier, REDIS_CMD_ATTCHMENT_DOWNLOAD_SET, _ATTCHMENT_DOWNLOAD_PREFIX, id, location);
	if (redis_ptr == NULL) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD ISSUE SET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr_carrier);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (strcasecmp(redis_ptr->str, "ok") == 0) {
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR SET _ATTCHMENT_DOWNLOADLOCATION FAILED: '%s' REPLY CODE:'%d'", __func__, pthread_self(), sesn_ptr_carrier, redis_ptr->str, redis_ptr->type);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief: for successfully uploaded attachment, store a permanent reference to its location for future download requests.
 * This is a permennant hash. The id cannot change, but location can, which is what is returned back to the user.
 *
 * @param sesn_ptr: must have full backend access context
 *
 * @dynamic_memory: on success, caller must free returnd 'char *'
 *
 */
UFSRVResult *
BackendAttachmentGetFileLocation (Session *sesn_ptr, const char *id)
{
	int 								rescode=RESCODE_PROG_NULL_POINTER;
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr;

	if (unlikely(sesn_ptr==NULL))		goto return_generic_error;
	if (unlikely((IS_EMPTY(id))))		goto return_error_param;

	pers_ptr=sesn_ptr->persistance_backend;

	redis_ptr=(*pers_ptr->send_command)(sesn_ptr, "GET %s:%s", _ATTCHMENT_DOWNLOAD_PREFIX, id);

	if (IS_EMPTY(redis_ptr)) {rescode=RESCODE_BACKEND_CONNECTION; goto return_error_backend_connection;}

	if (redis_ptr->type==REDIS_REPLY_STRING)
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', location:'%s'): Retrieved location...", __func__, pthread_self(), sesn_ptr, redis_ptr->str);
#endif
		char *file_location=strdup(redis_ptr->str);
		freeReplyObject(redis_ptr);

		 _RETURN_RESULT_SESN(sesn_ptr, file_location, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_error_backend_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_error_backend_nil;

	//catch-all
	goto	on_return_free;

	return_error_param:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "id or location");
	goto return_final;

	return_error_backend_connection:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', id:'%s'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, id);
	goto return_final;

	return_error_backend_error:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', id:'%s'): ERROR COULD NOT GET: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, id, redis_ptr->str);
	goto on_return_free;

	return_error_backend_nil:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', id:'%s'): ERROR COULD NOT GET: NIL REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, id, redis_ptr->str);
	goto on_return_free;

	on_return_free:
	freeReplyObject(redis_ptr);

	return_final:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

	return_generic_error:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Target Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief:	verify user supplied attachment path against the backend's stored value. For the attachment o be considered valid, both the
 * 	nonce and the path must be consistent with what was previously stored. The nonce is used as a key for the hashed path value.
 *
 * 	@params path: the full url, from which we derive the path
 */
bool
IsAttachmentDescriptionValid (Session *sesn_ptr, const char *nonce, const char *path)
{
	PersistanceBackend *pers_ptr;
	redisReply *redis_ptr;

	if (!IS_STR_LOADED(nonce)) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR: NONCE VALUE NOT SET", __func__, pthread_self(), sesn_ptr);
		return false;
	}

	pers_ptr = sesn_ptr->persistance_backend;

	char tmp[LBUF] = {0};
	snprintf(tmp, LBUF-1, "GET _ATTACHMENT:%s", nonce);

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, tmp))) {
	//if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, EDIS_CMD_REGONONCE_GET, prefix, nonce)))//buggy cause string corruption
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' nonce:'%s'): ERROR COULD NOT GET NONCE: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, nonce);

		return false;
	}

	__success_block:
	if (redis_ptr->type == REDIS_REPLY_STRING) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', path:'%s'}: SUCCESS NONCE:'%s' RECEIVED. Stored value:'%s'", __func__, pthread_self(), sesn_ptr, path, nonce, redis_ptr->str);
#endif

		char *this_path=strrchr(redis_ptr->str, '/');
		if (this_path++ && *this_path) {
			if (strcmp(this_path, path) == 0) {
				freeReplyObject(redis_ptr);
				return true;
			} else {
				syslog(LOG_DEBUG, LOGCSTR_ACCOUNT_ATTCH_NO_MATCH, __func__, pthread_self(), sesn_ptr, this_path, path,LOGCODE_ACCOUNT_ATTCH_NO_MATCH);
			}
		} else {
			syslog(LOG_DEBUG, LOGSTR_ACCOUNT_ATTCH_PATH_INVALID, __func__, pthread_self(), sesn_ptr, redis_ptr->str, this_path?this_path:"_undefined_", LOGCODE_ACCOUNT_ATTCH_PATH_INVALID);
		}

		freeReplyObject(redis_ptr);

		return false;
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	   syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD NOT GET NONCE: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, redis_ptr->str);

	   freeReplyObject(redis_ptr);

	   return false;
	}

	if (redis_ptr->type == REDIS_REPLY_NIL) {
	   syslog(LOG_DEBUG, "%s(pid:'%lu' o:'%p'): ERROR COULD NOT GET STORED NONCE: REPLY NIL '%s'", __func__, pthread_self(), sesn_ptr, redis_ptr->str);

	   freeReplyObject(redis_ptr);

	   return false;
	}

	return false;

}


