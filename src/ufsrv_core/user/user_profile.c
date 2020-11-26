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
#include <misc.h>
#include <uflib/db/db_sql.h>
#include <ufsrv_core/user/user_profile.h>
#include <ufsrv_core/user/user_backend.h>
#include <account_attribute_names.h>
#include <thread_context_type.h>
#include <utils_crypto.h>
#include <nportredird.h>
#include <hexcodec.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <uflib/db/dp_ops.h>
#include <utils_db_account.h>

extern __thread ThreadContext ufsrv_thread_context;
extern ufsrv	*const masterptr;


/**
 * @param is_decoded if flagged, key is returned in raw binary format, otherwise returned in base64 db stored format
 * @DYNAMIC_MEMORY: EXPORTS ProfileKeyStore * if not passed
 * @DYNAMIC_MEMORY: EXPORTS ProfileKeyStore.decoded * if is_decoded is true
 * @return profile key information from Db Backend
 */
ProfileKeyStore *
DbBackendGetProfileKey(Session *sesn_ptr, const UfsrvUid *uid_ptr, enum ProfileKeyFormattingCode key_formatting_code, ProfileKeyStore *key_store_out)
{
  DbAccountDataAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), ACCOUNT_JSONATTR_PROFILE_KEY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    char *profile_key_encoded = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
    if (*profile_key_encoded == '*')	 {
      free(SESSION_RESULT_USERDATA(sesn_ptr));
      return NULL;
    }

    ProfileKeyStore *key_store;
    if (IS_EMPTY(key_store_out))  key_store = calloc(1, sizeof(ProfileKeyStore));
    else                          key_store = key_store_out;

    if (key_formatting_code == KEY_RAW) {
      key_store->raw = base64_decode((const unsigned char *) profile_key_encoded, strlen(profile_key_encoded), (int *)&key_store->raw_sz);//to be free'd by user
      if (key_store->raw_sz == CONFIG_USER_PROFILEKEY_MAX_SIZE) return key_store;
      else {
        syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', profile_key:'%s', decoded_sz:'%lu'): ERROR: ERROR DECODING KEY", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, profile_key_encoded, key_store->raw_sz);
        free(key_store->raw);
        memset(key_store, '\0', sizeof(ProfileKeyStore));
        return NULL;
      }
    } else {
      strncpy(key_store->serialised, profile_key_encoded, CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED);//key is retrieved natively in b64
      free(profile_key_encoded);
    }

    return key_store;
  }

  return NULL;
}

UFSRVResult *
DbBackendSetProfileKey(Session *sesn_ptr, const char *profile_key_encoded)
{
  if (likely(strlen(profile_key_encoded) > CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED)) {
    if ((DbAccountUpdateData(sesn_ptr, ACCOUNT_JSONATTR_PROFILE_KEY, profile_key_encoded, SESSION_USERID(sesn_ptr))) == 0) {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
    } else {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
    }
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', key_sz:'%lu'): ERROR: PROFILE KEY TOO LONG", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), strlen(profile_key_encoded));
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONSTRAINT)
  }

}

/**
 * Extra logic to check for existing value and only update if it doesn't match, including if not set, where is_force_update flag is true
 * @param sesn_ptr
 * @param profile_key_encoded must be CONFIG_USER_ACCESS_TOKEN_MAX_SIZE
 * @param is_force_update if set where values don't match update stored with provided
 * @dynamic_memory: EXPORTs string if provided key mismatches stored one
 * @return
 */
UFSRVResult *
DbBackendSetProfileKeyIfNecessary(Session *sesn_ptr, const char *profile_key_encoded, bool is_force_update)
{
  if (unlikely((strlen(profile_key_encoded) > CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED))) {
    goto return_key_constraint;
  }

  ProfileKeyStore key_store = {0};
  DbBackendGetProfileKey(sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), KEY_B64_SERIALISED, &key_store);
  if (key_store.serialised[0] != '\0') {
    if (strncmp(key_store.serialised, profile_key_encoded, CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED) == 0) {
      goto return_do_thing;
    } else {
      if (is_force_update) {
        goto return_update_key;
      } else {
        goto return_stored_key;
      }
    }
  } else {
    goto return_update_key;
  }

  return_key_constraint:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', profile_sz:'%lu'): ERROR: PROFILE KEY TOO LONG", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), strlen(profile_key_encoded));
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONSTRAINT);

  return_do_thing:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EXISTINGSET)

  return_stored_key:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', token_provided:'%s', token_stored:'%s'): WARNING: Mismatched profile key: no force update flag: returning stored value", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), profile_key_encoded, key_store.serialised);
  _RETURN_RESULT_SESN(sesn_ptr, strndup(key_store.serialised, CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED), RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EXISTINGSET);

  return_update_key:
  DbBackendSetProfileKey(sesn_ptr, profile_key_encoded);
  SESSION_RESULT_USERDATA(sesn_ptr) = strdup(profile_key_encoded);
  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 *
 * @param jobj_account root node for account. Profile ky is stored in base64 encoded form
 * @param is_decoded whether the profile key should also be returned in binary decoded value in addition to the b64 encoded
 * @param store_in allocation to store returned value
 * @return on error NULL is returned
 * @dynamic_memory initial value is by reference to stored json value, then a copy is made
 * @dynamic_memory: ALLOCATES 'ProfileKeyStore *' if store_in wasn't provided
 * @dynamic_memory: ALLOCATES 'ProfileKeyStore.raw *' if 'is_decoded' is flagged
 */
ProfileKeyStore *
GetAccountAttributeForProfileKeyByStore(json_object *jobj_account, bool is_decoded, ProfileKeyStore *key_store_in)
{
  ProfileKeyStore *key_store = NULL;

  const char *profile_key_encoded = json_object_get_string(json__get(jobj_account, ACCOUNT_JSONATTR_PROFILE_KEY));
  if (IS_STR_LOADED(profile_key_encoded)) {
    if (IS_EMPTY(key_store_in)) {
      key_store = calloc(1, sizeof(ProfileKeyStore));
    }	else {
      key_store = key_store_in;
    }

    strncpy(key_store->serialised, profile_key_encoded, CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED);

    if (is_decoded) {
      key_store->raw = base64_decode((const unsigned char *) profile_key_encoded, strlen(key_store->serialised), (int *)&key_store->raw_sz);

      if (key_store->raw_sz == CONFIG_USER_PROFILEKEY_MAX_SIZE) return key_store;
      else {
        syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', profile_key:'%s', decoded_sz:'%lu'): ERROR: ERROR DECODING KEY", __func__, pthread_self(), THREAD_CONTEXT_PTR, profile_key_encoded, key_store->raw_sz);
        free(key_store->raw);
        memset(key_store, '\0', sizeof(ProfileKeyStore));
        return NULL;
      }
    }
  }

  return key_store;
}

/**
 * @brief Query the provided json object for the profile key. Since the returned value is destroyed when json object is deallocated,
 * user must retain a copy locally if required.
 * @param jobj_account
 * @dynamic_memory value returned by reference to stored json value
 */
__unused const char *
GetAccountAttributeForProfileKey (json_object *jobj_account)
{
  const char *profile_key_encoded = json_object_get_string(json__get(jobj_account, ACCOUNT_JSONATTR_PROFILE_KEY));
  if (IS_STR_LOADED(profile_key_encoded)) {
    return profile_key_encoded;
  }

  return   NULL;
}

static UFSRVResult *_DbAccountSetProfileAuthDescriptor(unsigned long userid, const UserProfileAuthDescriptor *profile_descriptor);
static UFSRVResult *_DbAccountGetProfileAuthDescriptor(DbOpDescriptor *dbop_descriptor);

static char *
_UuidDbOpQueryProvider(intptr_t values[])
{
#define SQL_SELECT_UUID 	 "SELECT uuid, uuid_serialised FROM accounts WHERE number = '%s'"
  char *sql_query_str = mdsprintf(SQL_SELECT_UUID, (char *)values[0]);

  return sql_query_str;
#undef SQL_SELECT_UUID
}

static char *
_UuidDbOpQueryProviderByUserId(intptr_t values[])
{
#define SQL_SELECT_UUID 	 "SELECT uuid, uuid_serialised FROM accounts WHERE id = '%lu'"
  char *sql_query_str = mdsprintf(SQL_SELECT_UUID, (unsigned long)values[0]);

  return sql_query_str;
#undef SQL_SELECT_UUID
}

/**
 * Standard by-ref transformer for stored uuid values
 * @param dbop_descriptor
 * @return
 */
static int _UuidDbOpTransformer(DbOpDescriptor *dbop_descriptor)
{
#define COLUMN_UUID		((uint8_t *)((struct _h_type_blob *)result->data[0][0].t_data)->value)
#define COLUMN_UUID_LENGTH	((struct _h_type_blob *)result->data[0][0].t_data)->length
#define COLUMN_UUID_SERIALISED	((struct _h_type_text *)result->data[0][1].t_data)->value

  struct _h_result *result = &dbop_descriptor->result;
  Uuid *uuid = (Uuid *)dbop_descriptor->ctx_data;

  uuid->raw.by_ref = (uuid_t *)COLUMN_UUID;
  uuid->serialised.by_ref = COLUMN_UUID_SERIALISED;

  return 0;

#undef COLUMN_UUID
#undef COLUMN_UUID_LENGTH
#undef COLUMN_UUID_SERIALISED
}

/**
 * Retrieve Uuid values for user. Values returned by-ref, so upstream must call finaliser on db result object.
 * @param username query parameter
 * @param uuid_in preallocated by user to store transformed uuid value
 * @param db_descriptor_in preallocated dbop context
 * @return
 * @dynamic_memory _h_result * object
 */
Uuid *
GetUuid(const char *username, Uuid *uuid_in, DbOpDescriptor *db_descriptor_in)
{
  DbOpDescriptor *db_descriptor = db_descriptor_in;
  db_descriptor->ctx_data = CLIENT_CTX_DATA(uuid_in);
  db_descriptor->transformer.transform = _UuidDbOpTransformer;
//  db_descriptor->finaliser.finalise    = GetDefaultDbOpResultFinaliser();//don't set it, otherwise it will be automatically called after transformation

  db_descriptor->query_provider.provide = _UuidDbOpQueryProvider;
  db_descriptor->query_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(username), 0};
  db_descriptor->query_provider.finalise = GetDefaultQueryProviderFinalser;

  DbAccountGetUuid(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser();
    return uuid_in;
  }

  return NULL;
}

Uuid *
GetUuidByUserId(unsigned long uid, Uuid *uuid_in, DbOpDescriptor *db_descriptor_in)
{
  DbOpDescriptor *db_descriptor = db_descriptor_in;
  db_descriptor->ctx_data = CLIENT_CTX_DATA(uuid_in);
  db_descriptor->transformer.transform = _UuidDbOpTransformer;
//  db_descriptor->finaliser.finalise    = GetDefaultDbOpResultFinaliser();//don't set it, otherwise it will be automatically called after transformation

  db_descriptor->query_provider.provide = _UuidDbOpQueryProviderByUserId;
  db_descriptor->query_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(uid), 0};
  db_descriptor->query_provider.finalise = GetDefaultQueryProviderFinalser;

  DbAccountGetUuid(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser();
    return uuid_in;
  }

  return NULL;
}

/**
 *
 * @param cred_request_serialised encoded in HEX
 * @param cred_request_in Return object allocated by user
 * @return
 */
ProfileCredentialRequest *
DeserialiseProfileCredentialRequest(const char *cred_request_serialised, ProfileCredentialRequest *cred_request_in)
{
  ProfileCredentialRequest *cred_request;
  if (IS_EMPTY(cred_request_in)) cred_request = calloc(1, sizeof(ProfileCredentialRequest));
  else cred_request = cred_request_in;

  if (hex_decode(cred_request->request.raw, (const unsigned char *)cred_request_serialised, strlen(cred_request_serialised)) == 0) {
    return cred_request;
  } else {
    if (IS_EMPTY(cred_request_in)) free(cred_request);
    syslog(LOG_ERR, "%s: (request:'%s'): ERROR DESERIALISING REQUEST...", __func__, cred_request_serialised);
  }

  return NULL;
}

UserProfileAuthDescriptor *
UserProfileAuthDescriptorFromJson(json_object *jobj, UserProfileAuthDescriptor *profile_descriptor_in)
{
  UserProfileAuthDescriptor *profile_descriptor;

  if (IS_EMPTY(profile_descriptor_in)) profile_descriptor = calloc(1, sizeof(UserProfileAuthDescriptor));
  else profile_descriptor = profile_descriptor_in;

  profile_descriptor->commitment.serialised_ref = (uint8_t *)json_object_get_string(json__get(jobj, "commitment"));
  profile_descriptor->version.serialised_ref = (uint8_t *)json_object_get_string(json__get(jobj, "version"));

  if (IS_STR_LOADED(profile_descriptor->commitment.serialised_ref) && IS_STR_LOADED(profile_descriptor->version.serialised_ref)) {
    profile_descriptor->commitment.accessor.get_serialised = UserProfileAuthDescriptorGetCommitmentSerialisedByRef;
    profile_descriptor->version.accessor.get_serialised = UserProfileAuthDescriptorGetVersionSerialisedByRef;

    return profile_descriptor;
  } else goto clean_up;

  clean_up:
  if (IS_EMPTY(profile_descriptor_in)) free(profile_descriptor);
  return NULL;
}

UFSRVResult *
StoreUserProfileAuthDescriptor(unsigned long userid, const UserProfileAuthDescriptor *profile_descriptor)
{
  return _DbAccountSetProfileAuthDescriptor(userid, profile_descriptor);
}

static UFSRVResult *_RetrieveUserProfileAuthDescriptor(unsigned long userid, UserProfileAuthDescriptor *profile_descriptor, DbOpDescriptor *dbop_descriptor);
static int _UserProfileAuthDescriptorDpOpTransformer(DbOpDescriptor *dbop_descriptor);
static char *_UserProfileAuthProfileDescriptorQueryProvider(intptr_t values[]);

/**
 *
 * @param userid
 * @param profile_cred_request must be raw encoded
 * @param profile_cred_response_in
 * @return fully constructed ProfileCredentialResponse * free from any local references
 * @dynamic_memory EXPORTS  ProfileCredentialResponse * if profile_cred_response_in was NULL
 */
ProfileCredentialResponse *
GetProfileKeyCredential(UfsrvUid *ufsrv_uid, ProfileCredentialRequest *profile_cred_request, char *profile_version, ProfileCredentialResponse *profile_cred_response_in)
{
  if (IS_EMPTY(profile_cred_request)) return NULL;

  UserProfileAuthDescriptor profile_auth_descriptor = {0};
  DbOpDescriptor db_descriptor = {0};
  profile_auth_descriptor.version.serialised_ref = (uint8_t  *)profile_version;
  _RetrieveUserProfileAuthDescriptor(UfsrvUidGetSequenceId(ufsrv_uid), &profile_auth_descriptor, &db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    ProfileCredentialResponse *profile_cred_response = IS_EMPTY(profile_cred_response_in) ?
                                                       calloc(1, sizeof(ProfileCredentialResponse)):
                                                       profile_cred_response_in;

    uint8_t random_bytes[RANDOMNESS_LEN] = {0};
    GenerateSecureRandom(random_bytes, RANDOMNESS_LEN);
    int ffi_result = FFI_ServerSecretParams_issueProfileKeyCredentialDeterministic(MASTER_CONF_SERVER_PRIVATE_PARAMS, SERVER_SECRET_PARAMS_LEN,
                                                                                   random_bytes, RANDOMNESS_LEN,
                                                                                   profile_cred_request->request.raw, PROFILE_KEY_CREDENTIAL_REQUEST_LEN,
                                                                                   (uint8_t *)profile_auth_descriptor.uuid.raw.by_ref, UUID_LEN,
                                                                                   profile_auth_descriptor.commitment.raw, PROFILE_KEY_COMMITMENT_LEN,
                                                                                   profile_cred_response->response.raw, PROFILE_KEY_CREDENTIAL_RESPONSE_LEN);
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER(&db_descriptor);

    if (ffi_result == FFI_RETURN_OK) {
      return profile_cred_response;
    }

    return_error_profile_cred:
    syslog(LOG_ERR, "%s: (th_ctx:'%p, ffi_result:'%d', commitment:'%s', uuid:'%s'): ERROR ISSUING ProfileKeyCredential...", __func__, THREAD_CONTEXT_PTR, ffi_result, profile_auth_descriptor.commitment.serialised_ref, profile_auth_descriptor.uuid.serialised.by_ref);
    if (IS_EMPTY(profile_cred_response_in)) free(profile_cred_response);
  }

  return NULL;
}

/**
 *
 * @param userid
 * @param profile_descriptor_in
 * @return UserProfileAuthDescriptor * marshalled through UFSRVResult
 * @dynamic_memory: EXPORTS serProfileAuthDescriptor * if profile_descriptor_in is NULL
 */
static UFSRVResult *
_RetrieveUserProfileAuthDescriptor(unsigned long userid, UserProfileAuthDescriptor *profile_descriptor, DbOpDescriptor *dbop_descriptor)
{
  dbop_descriptor->ctx_data = profile_descriptor;
  dbop_descriptor->transformer.transform = _UserProfileAuthDescriptorDpOpTransformer;

  dbop_descriptor->query_provider.provide= _UserProfileAuthProfileDescriptorQueryProvider;
  dbop_descriptor->query_provider.values = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(userid), 0};
  dbop_descriptor->query_provider.finalise = GetDefaultQueryProviderFinalser();

  _DbAccountGetProfileAuthDescriptor(dbop_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA || THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL_(RESCODE_BACKEND_DATA_TRANSFORMATION)) {
    dbop_descriptor->finaliser.finalise    = GetDefaultDbOpResultFinaliser();
  }

  return THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context);

}

static  char *
_UserProfileAuthProfileDescriptorQueryProvider(intptr_t values[])
{
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')), JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')), uuid, uuid_serialised FROM accounts WHERE id = %lu"
  char *sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, ACCOUNT_JSONATTR_PROFILE_COMMITMENT, ACCOUNT_JSONATTR_PROFILE_VERSION, (unsigned long)values[0]);

  return sql_query_str;
#undef SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
}

/**
 * Query lifecycle call back for transferring raw DB resultset to client context.
 * @param dbop_descriptor DB operation query context
 * @param profile_descriptor_in client context passed by client to hold transferred data.
 */
static int
_UserProfileAuthDescriptorDpOpTransformer(DbOpDescriptor *dbop_descriptor)
{
#define SQL_QUERY_COMMITMENT	((struct _h_type_blob *)result->data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_COMMITMENT_VALUE ((struct _h_type_blob *)result->data[0][0].t_data)->value
#define SQL_QUERY_COMMITMENT_VALUE_LENGTH	((struct _h_type_blob *)result->data[0][0].t_data)->length
#define SQL_QUERY_VERSION	((struct _h_type_blob *)result->data[0][1].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_VERSION_VALUE ((struct _h_type_blob *)result->data[0][1].t_data)->value
#define SQL_QUERY_VERSION_VALUE_LENGTH	((struct _h_type_blob *)result->data[0][1].t_data)->length
#define	SQL_QUERY_UUID_VALUE ((struct _h_type_blob *)result->data[0][2].t_data)->value
#define SQL_QUERY_UUID_VALUE_LENGTH	((struct _h_type_blob *)result->data[0][2].t_data)->length
#define	SQL_QUERY_UUID_SERIALISED_VALUE ((struct _h_type_text *)result->data[0][3].t_data)->value

  struct _h_result *result = &dbop_descriptor->result;
  UserProfileAuthDescriptor *profile_descriptor = (UserProfileAuthDescriptor *)dbop_descriptor->ctx_data;

  if (likely(SQL_QUERY_VERSION && SQL_QUERY_VERSION_VALUE_LENGTH == PROFILE_KEY_VERSION_ENCODED_LEN)) {
    if (IS_STR_LOADED(profile_descriptor->profile_key.serialised_ref)) {
      if (strncmp((const char *) profile_descriptor->profile_key.serialised_ref,
                  ((struct _h_type_blob *) result->data[0][1].t_data)->value, PROFILE_KEY_VERSION_ENCODED_LEN) != 0) {
        syslog(LOG_ERR, "%s (pid:'%lu', th_ctx:'%p', provided:'%s', stored:'%s'): ERROR MISMATCHED PROFILE VERSIONS", __func__, pthread_self(), THREAD_CONTEXT_PTR, profile_descriptor->profile_key.serialised_ref,  (const char *)((struct _h_type_blob *) result->data[0][1].t_data)->value);
        dbop_descriptor->dbop_status.status = TRANSFORMER_ERROR;
        goto return_final;
      }
    } else {
      profile_descriptor->version.serialised_ref = (uint8_t *)SQL_QUERY_VERSION_VALUE;
      profile_descriptor->version.accessor.get_serialised = UserProfileAuthDescriptorGetVersionSerialisedByRef;
    }
  }

  if (SQL_QUERY_COMMITMENT && SQL_QUERY_COMMITMENT_VALUE_LENGTH > 0) {
    profile_descriptor->commitment.serialised_ref = (uint8_t *)SQL_QUERY_COMMITMENT_VALUE;
    profile_descriptor->commitment.accessor.get_serialised = UserProfileAuthDescriptorGetCommitmentSerialisedByRef;

    int decoded_sz = 0;
    //IMPORTANT: always use nominal size on returned blobs, not strlen() because db blobs (even with strings) are not null terminated
      base64_decode_buffered(profile_descriptor->commitment.serialised_ref, SQL_QUERY_COMMITMENT_VALUE_LENGTH, profile_descriptor->commitment.raw, &decoded_sz);
    if (decoded_sz != PROFILE_KEY_COMMITMENT_LEN) {
      dbop_descriptor->dbop_status.status = TRANSFORMER_ERROR;
      syslog(LOG_ERR, "%s (pid:'%lu', th_ctx:'%p', decoded_sz:'%d', commitment:'%s'): ERROR DECODING PROFILE COMMITMENT (IS DECODED_SZ = 97?)", __func__, pthread_self(), THREAD_CONTEXT_PTR, decoded_sz,  profile_descriptor->commitment.serialised_ref);
    }
  }

  profile_descriptor->uuid.raw.by_ref = SQL_QUERY_UUID_VALUE;
  profile_descriptor->uuid.serialised.by_ref = SQL_QUERY_UUID_SERIALISED_VALUE;

  return_final:
  return 0;
  //since we are transferring by ref don't invoke result finaliser

#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef 	SQL_QUERY_ATTRIBUTE
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

static UFSRVResult *
_DbAccountGetProfileAuthDescriptor(DbOpDescriptor *dbop_descriptor)
{
  GetDbResult(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

static UFSRVResult *
_DbAccountSetProfileAuthDescriptor(unsigned long userid, const UserProfileAuthDescriptor *profile_descriptor)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET data = JSON_REPLACE(data, '$.%s', '%s'),  data = JSON_REPLACE(data, '$.%s', '%s') WHERE id =' %lu'"

  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, ACCOUNT_JSONATTR_PROFILE_COMMITMENT, (*profile_descriptor->commitment.accessor.get_serialised)(profile_descriptor), ACCOUNT_JSONATTR_PROFILE_VERSION, (*profile_descriptor->version.accessor.get_serialised)(profile_descriptor), userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s  GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s  ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
  }

  free (sql_query_str);

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA)

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

UserProfileAuthDescriptor *
AllocateUserProfileAuthWithByRefAccess()
{
  UserProfileAuthDescriptor *profile_desc = calloc(1, sizeof(UserProfileAuthDescriptor));
  profile_desc->profile_key.accessor.get_serialised = UserProfileAuthDescriptorGetProfileKeySerialisedByRef;
  profile_desc->commitment.accessor.get_serialised = UserProfileAuthDescriptorGetCommitmentSerialisedByRef;
  profile_desc->version.accessor.get_serialised = UserProfileAuthDescriptorGetVersionSerialisedByRef;

  return profile_desc;
}

const uint8_t *UserProfileAuthDescriptorGetProfileKeySerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->profile_key.serialised_ref;
}

const uint8_t *UserProfileAuthDescriptorGetProfileKeySerialised(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->profile_key.serialised;
}

const uint8_t *UserProfileAuthDescriptorGetCommitmentSerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->commitment.serialised_ref;
}

const uint8_t *UserProfileAuthDescriptorGetCommitmentSerialised(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->commitment.serialised;
}

const uint8_t *UserProfileAuthDescriptorGetVersionSerialised(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->version.serialised;
}

const uint8_t *UserProfileAuthDescriptorGetVersionSerialisedByRef(const UserProfileAuthDescriptor *profile_descriptor)
{
  return profile_descriptor->version.serialised_ref;
}