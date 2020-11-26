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

#ifndef INCLUDE_USER_BACKEND_H_
#define INCLUDE_USER_BACKEND_H_

#include <account_attribute_names.h>
#include <utils.h>
#include <session_type.h>
#include <ufsrvuid_type.h>
#include <session_service.h>
#include <uuid_type.h>
#include <json/json.h>
#include <uflib/db/db_op_descriptor_type.h>

//first device profile created during registration
#define DEFAULT_DEVICE_ID	1

#define RESULT_IS_SUCCESS_THRCTX  (THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context)->result_type == RESULT_TYPE_SUCCESS)
#define RESULT_USERDATA_THCTX      (_RESULT_USERDATA(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context)))
#define RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX  RESULT_IS_SUCCESS_WITH_BACKEND_DATA(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context))
#define RESULT_IS_SUCCESS_WITH_BACKEND_DATA(x) ((x)->result_type == RESULT_TYPE_SUCCESS && (x)->result_code == RESCODE_BACKEND_DATA)
#define SESSION_RESULT_IS_SUCCESS_WITH_BACKEND_DATA(x) ((x)->sservice.result.result_type == RESULT_TYPE_SUCCESS && (x)->sservice.result.result_code == RESCODE_BACKEND_DATA)

//set a temporary expiration for the pending accountg cookie coocki verification_code
#define REDIS_CMD_PENDINGACCTCOOKIE_SET	"SET PENDINGACCT_COOKIE:%s %d EX %lu"

//get pending account cookie
#define REDIS_CMD_PENDINGACCTCOOKIE_GET	"GET PENDINGACCT_COOKIE:%s"

#define REDIS_CMD_PENDINGACCTCOOKIE_DEL	"DEL PENDINGACCT_COOKIE:%s"

//just a carrier structure to facilitate shifting of data stored in db against user accounts. Field widths are inline with
//db fields
struct DbUserAccount {
	unsigned  device_id;
	unsigned registration_id;
	char username[MBUF];//number
	char password[MBUF];
	char salt[MBUF];
	char authentication_token[MBUF];
	char signalling_key[MBUF];
	char *gcm_id[MBUF];//cloud messaging id
	long long created;
	int fetches_msg:1;
};
typedef struct DbUserAccount DbUserAccount;

struct DbPendingAccount {
	unsigned 			ufsrv_geogroup;//geogrphical location for nearest data centre
	int 			    device_id;
	unsigned long	userid;
	UfsrvUid      ufsrvuid;
	Uuid          uuid;
	VerificationCode	verification_code;

	char								*username;
	char								*password;
	char 								*e164number;
	char								*cookie;
	char                *nickname;
	time_t 							when;
	enum AccountRegoStatus	rego_status;
};
typedef struct DbPendingAccount  PendingAccount;
typedef struct DbPendingAccount  AuthenticatedAccount;

struct AccountKeyRecord {
	int rego_id;
	bool is_lastresort;
	int key_id;
	int device_id;
	char *ufsrvuid;//encoded
	char *public_key;
};
typedef struct AccountKeyRecord AccountKeyRecord;

struct AccountKeyRecordSigned {
	AccountKeyRecord key;
	char *signature;
};
typedef struct AccountKeyRecordSigned AccountKeyRecordSigned;


typedef struct DeviceRecord {
	int device_id;
	char *name;
	time_t when_lastseen;
	time_t when_created;
} DeviceRecord;

//used when querying user id information directly from the db
typedef struct DbBackendUfsrvUidDescriptor {
  bool          is_ufsrvuid_set;
  uint8_t       ufsrvid[CONFIG_MAX_UFSRV_ID_SZ]; //raw id as stored in db
  unsigned long sequence_id; //db generated id
  Uuid          uuid;
} DbBackendUfsrvUidDescriptor;

//uses sttaic refernce,not pointer
#define PENDINGACCOUNT_USERNAME(x) (x.username)
#define PENDINGACCOUNT_PASSWORD(x) (x.password)
#define PENDINGACCOUNT_COOKIE(x) (x.cookie)

#define PENDINGACCOUNT_PTR_USERNAME(x)    (x->username)
#define PENDINGACCOUNT_PTR_PASSWORD(x)    (x->password)
#define PENDINGACCOUNT_PTR_COOKIE(x)      (x->cookie)
#define PENDINGACCOUNT_PTR_REGO_STATUS(x) ((x)->rego_status)
#define PENDINGACCOUNT_PTR_E164_NUMEBR(x) ((x)->e164number)
#define PENDINGACCOUNT_PTR_NICKNAME(x) 		((x)->nickname)
#define AUTHACCOUNT_USERNAME(x) (x->username)
#define AUTHACCOUNT_PASSWORD(x) (x->password)
#define AUTHACCOUNT_COOKIE(x) (x->cookie)
#define AUTHACCOUNT_USERID(x) (x->userid)
#define AUTHACCOUNT_UFSRVUID(x) (x->ufsrvuid)


//_NAMESPACE_BACKEND_NICKNAMES
#define REDIS_CMD_NICKNAMES_DIRECTORY_SET "HSET _NICKNAMES_DIRECTORY %s %lu"
#define REDIS_CMD_NICKNAMES_DIRECTORY_GET "HGET _NICKNAMES_DIRECTORY %s"
#define REDIS_CMD_NICKNAMES_DIRECTORY_DEL	"HDEL _NICKNAMES_DIRECTORY %s"

//hset directo token {token:"xxx", ..}
//#define REDIS_CMD_ACCOUNTS_DIRECTORY_SET "HSET PROFILES_DIRECTORY %s %s"
//SHA-1, b64 encoded token token userid
#define REDIS_CMD_ACCOUNTS_DIRECTORY_SET "HSET USERNAMES_TOKENS_DIRECTORY %s %s:%lu"

//hget directo token
#define REDIS_CMD_ACCOUNTS_DIRECTORY_GET 		"HGET USERNAMES_TOKENS_DIRECTORY %s"
#define REDIS_CMD_ACCOUNTS_DIRECTORY_DEL		"HDEL USERNAMES_TOKENS_DIRECTORY %s"
#define REDIS_CMD_ACCOUNTS_DIRECTORY_GETALL "HKEYS USERNAMES_TOKENS_DIRECTORY"

UFSRVResult *ReturnUfsrvResultFromDbOpDescriptor(const DbOpDescriptor *dbop_descriptor);
struct json_object *BackendDirectorySharedContactsGet (Session *sesn_ptr, struct json_object *jobj_contacts, const char *user_name);
UFSRVResult *BackendDirectoryContactTokenGet (Session *sesn_ptr, const char *contact_token);
UFSRVResult *BackendDirectoryContactTokenDel (Session *sesn_ptr, const char *contact_token);

enum AccountRegoStatus GetAccountRegisterationStatus(Session *sesn_ptr, const char *username);

UFSRVResult *DbAccountGetE164Number (Session *sesn_ptr, unsigned long userid);
int DbAccountSetE164Number (Session *sesn_ptr, unsigned long userid, const char *e164number);
UFSRVResult *DbValidateUserId (Session *sesn_ptr, unsigned long userid);
bool IsUserIdValid (Session *sesn_ptr, unsigned long userid);
UFSRVResult *DbValidateUserSignOnWithCookie (Session *, const char *, AuthenticatedAccount *acct_ptr, UFSRVResult *);
UFSRVResult *DbAuthenticateUser (Session *sesn_ptr, unsigned long, char *password, const char *cookie, unsigned);
UFSRVResult *DbGetUserByUsername (const char *username, unsigned long call_flags);
size_t (*GetDefaultBackendResponse()) (void *,size_t, size_t, void *);

const char *GetAccountAttributeForCloudMessaging (json_object *jobj_account, unsigned int device_id);

int AccountSignOnUser (Session *sesn_ptr, AuthenticatedAccount *authacct_ptr);

void PendingAccountMemDestruct (PendingAccount *pacct_ptr, bool self_destruct_flag);
void AuthenticatedAccountMemDestruct (AuthenticatedAccount *pacct_ptr, bool self_destruct_flag);
UFSRVResult *DbDeleteUserAccount (Session *sesn_ptr, unsigned long);
int DbDeletePendingAccount (Session *sesn_ptr, const char *username);
int DbSetPendingAccountRegoStatus (Session *sesn_ptr, const PendingAccount *);
UFSRVResult *DbAccountDeactivate (Session  *sesn_ptr, const UfsrvUid *, bool flag_nuke);
PendingAccount *DbCreateNewAccount (Session *sesn_ptr,  const char *email, const char *username, const char *password, const char *nonce);
UFSRVResult *DbGetPendingAccountVerificationCode (Session *sesn_ptr, PendingAccount *pending_acct_ptr);

UFSRVResult *DbAccountGetUfrsvUid (Session *sesn_ptr, const char *username, UfsrvUid *uid_ptr_out);
UFSRVResult *DbAccountGetUserId(Session *sesn_ptr, const char *username, DbBackendUfsrvUidDescriptor *uid_descriptor_out);
UFSRVResult *DbAccountGetUuid (DbOpDescriptor *);

enum AccountRegoStatus GetAccountVerificationStatus(Session *sesn_ptr, PendingAccount *);
bool PendingAccountVerify (Session *sesn_ptr, PendingAccount *pacct_ptr, int rego_code, bool);
UFSRVResult *CachebackendGetPendingAccountCookie (Session *sesn_ptr, const char *cookie, bool is_return_code);
UFSRVResult *CachebackendDelPendingAccountCookie (Session *sesn_ptr, const char *cookie);
UFSRVResult *UpgradePendingAccountByJson(Session *sesn_ptr, PendingAccount *pending_account, struct json_object *jobj, bool);
int SetUserKeys (Session *sesn_ptr, const UfsrvUid *uid_ptr, json_object *jobj, int device_id);
int DbSetKeys (Session *sesn_ptr, const char *number, unsigned long device_id, unsigned long key_id, const char *public_key, int last_resort_key_flag);
int DbSetGcmId (Session *sesn_ptr, const UfsrvUid *, int device_id, const char  *gcm_id);
char *DbGetGcmId (Session *sesn_ptr, const UfsrvUid *, int device_id);
long long DbGetWhenCreated (Session *sesn_ptr, const UfsrvUid *, int device_id);
UFSRVResult *DbGetGcmIdMulti (Session *sesn_ptr, CollectionDescriptor *collection_ptr_in, CollectionDescriptor *collection_ptr_out);
int BackendSetAuthenticationMode (Session *sesn_ptr, const char *, int authmode);
UFSRVResult *BackendDirectoryContactTokenSet (Session *sesn_ptr, const char *username, unsigned long);

int DbAccountUserDataUpdatePreference (Session *sesn_ptr,  UserPreferenceDescriptor *pref_ptr, unsigned long userid);
UFSRVResult *DbAccountGetKeysCountForDevice (Session *sesn_ptr, const char *number, int device_id);
UFSRVResult *DbAccountGetFirstAvailableKeyByDevice (Session *sesn_ptr, const char *number, int device_id);
UFSRVResult *DbAccountDeleteKey (Session *sesn_ptr, int key_id);
UFSRVResult *DbAccountDeleteKeys (Session *sesn_ptr, const char *username, int device_id);
void AccountKeyRecordDestruct (AccountKeyRecord *account_key_ptr, bool self_destruct);
void AccountKeyRecordSignedDestruct (AccountKeyRecordSigned *saccount_key_ptr, bool self_destruct);
UFSRVResult *DbAccountIdentityKeyGet (Session *sesn_ptr, const UfsrvUid *, int device_id);
UFSRVResult *DbAccountSignedPreKeySet (Session *sesn_ptr, const UfsrvUid *, int device_id, struct json_object *);
UFSRVResult *DbAccountSignedPreKeyGet (Session *sesn_ptr, const UfsrvUid *, int device_id);
struct AccountKeyRecordSigned *AccountSignedPreKeyGet (Session *sesn_ptr, const UfsrvUid *, int device_id);
struct json_object *AccountSignedPreKeyGetInJson (Session *sesn_ptr, const UfsrvUid *, int device_id);

const char *DbBackendGetAccessToken(Session *sesn_ptr, const UfsrvUid *, bool is_encoded);
UFSRVResult *DbBackendSetAccessToken (Session *sesn_ptr, const char *profile_key_encoded);
UFSRVResult *DbBackendSetAccessTokenIfNecessary (Session *sesn_ptr, const char *access_token_encoded, bool is_force_update);

UFSRVResult *BackendDirectoryNicknameSet (Session *sesn_ptr, const char *nickname);
UFSRVResult *BackendDirectoryNicknameGet (Session *sesn_ptr, const char *nickname);
UFSRVResult *BackendDirectoryNicknameDel (Session *sesn_ptr, const char *);
bool IsNicknameAvailable (Session *sesn_ptr, const char *nickname);
UFSRVResult *AccountNicknameValidateForUniqueness(Session *sesn_ptr, const UfsrvUid *, const char *nickname_by_user);

#endif /* SRC_INCLUDE_USER_BACKEND_H_ */
