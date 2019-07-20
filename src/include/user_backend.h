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

#ifndef INCLUDE_USER_BACKEND_H_
#define INCLUDE_USER_BACKEND_H_

#include <utils.h>
#include <session_type.h>
#include <ufsrvuid_type.h>
#include <session_service.h>

#include <json/json.h>

//first device profile created during registration
#define DEFAULT_DEVICE_ID	1

#define RESULT_IS_SUCCESS_THRCTX  (THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context)->result_type == RESULT_TYPE_SUCCESS)
#define RESULT_USERDATA_THCTX      (_RESULT_USERDATA(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context)))
#define RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX  RESULT_IS_SUCCESS_WITH_BACKEND_DATA(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context))
#define RESULT_IS_SUCCESS_WITH_BACKEND_DATA(x) ((x)->result_type == RESULT_TYPE_SUCCESS && (x)->result_code == RESCODE_BACKEND_DATA)
#define SESSION_RESULT_IS_SUCCESS_WITH_BACKEND_DATA(x) ((x)->sservice.result.result_type == RESULT_TYPE_SUCCESS && (x)->sservice.result.result_code == RESCODE_BACKEND_DATA)

//increment nonce counter by 1 returns incremented counter
#define REDIS_CMD_REGONONCE_INC_COUNTER	"INCRBY NONCE_REGO_COUNTER 1"

#define EDIS_CMD_REGONONCE_EXPIRE	"EXPIRE %s %d"
//set nonce sesnid with expiry vlue
#define EDIS_CMD_REGONONCE_SET	"SET %s:%s	%lu EX %lu"
#define EDIS_CMD_REGONONCE_GET	"GET %s:%s"
#define REDIS_CMD_REGONONCE_DEL	"DEL %s:%s"

//set a temporary expiration for the pending accountg cookie coocki verification_code
#define REDIS_CMD_PENDINGACCTCOOKIE_SET	"SET PENDINGACCT_COOKIE:%s %d EX %lu"

//get pending account cookie
#define REDIS_CMD_PENDINGACCTCOOKIE_GET	"GET PENDINGACCT_COOKIE:%s"

#define REDIS_CMD_PENDINGACCTCOOKIE_DEL	"DEL PENDINGACCT_COOKIE:%s"

#define AUTHENTICATED_DEVICE 					0
#define ACCOUNT_JSONATTR_ID						"id"
#define ACCOUNT_JSONATTR_ACCOUNT_STATE  "account_state"
#define ACCOUNT_JSONATTR_SESSION_STATE  "session_state"
#define ACCOUNT_JSONATTR_USERID				"userid"
#define ACCOUNT_JSONATTR_EID  				"eid"
#define ACCOUNT_JSONATTR_UFSRVUID			"ufsrvuid"
#define ACCOUNT_JSONATTR_REGO_ID			"registration_id"
#define ACCOUNT_JSONATTR_AUTH_TOKEN		"authentication_token"
#define ACCOUNT_JSONATTR_SALT					"salt"
#define ACCOUNT_JSONATTR_COOKIE				"cookie"
#define ACCOUNT_JSONATTR_SIGNED_PREKY	"signed_prekey"
#define ACCOUNT_JSONATTR_GCM_ID				"gcm_id"
#define ACCOUNT_FETCHES_MSG						"fetches_messages"
#define ACCOUNT_JSONATTR_NUMBER 			"number"
#define ACCOUNT_JSONATTR_CREATED			"created"
#define ACCOUNT_JSONATTR_LASTSEEN			"lastseen"
#define ACCOUNT_JSONATTR_USER_AGENT		"user_agent"
#define ACCOUNT_JSONATTR_IDENTITY_KEY	"identityKey"
#define ACCOUNT_JSONATTR_NICKNAME			"nickname"
#define ACCOUNT_JSONATTR_PROFILE_KEY	"profile_key"
#define ACCOUNT_JSONATTR_ACCESS_TOKEN	"access_token" //user access token derived from profile key provided by owner during registration. Otherusers can derive to prove knowledge of profile
#define ACCOUNT_JSONATTR_REGO_STATUS	"rego_status"
#define ACCOUNT_JSONATTR_AVATAR       "avatar"
#define ACCOUNT_JSONATTR_PREFS_BOOL   "prefs_bool"
#define ACCOUNT_JSONATTR_E164NUMBER 	"e164number"
#define ACCOUNT_JSONATTR_USERNAME 		"username"
#define ACCOUNT_JSONATTR_PASSWORD     "password"
#define ACCOUNT_JSONATTR_NONCE        "nonce"
#define ACCOUNT_JSONATTR_E164NUMBER 	"e164number"
#define ACCOUNT_JSONATTR_REGO_PIN     "rego_pin"
#define ACCOUNT_JSONATTR_BASELOC_ZONE  "baseloc_zone"
#define ACCOUNT_JSONATTR_GEOLOC_TRIGGER "geoloc_trigger"
#define ACCOUNT_JSONATTR_UNSOLICITED_CONTACT  "unsolicited_contact"

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

typedef struct ProfileKeyStore {
  char profile_key_encoded[CONFIG_USER_PROFILEKEY_MAX_SIZE+1]; //extra for '\0'
  unsigned char *profile_key_decoded;
} ProfileKeyStore;

//used when querying user id information directly from the db
typedef struct DbBackendUfsrvUidDescriptor {
  bool          is_ufsrvuid_set;
  uint8_t       ufsrvid[CONFIG_MAX_UFSRV_ID_SZ]; //raw id as stored in db
  unsigned long sequence_id; //db generated id
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

struct json_object *BackendDirectorySharedContactsGet (Session *sesn_ptr, struct json_object *jobj_contacts, const char *user_name);
UFSRVResult *BackendDirectoryContactTokenGet (Session *sesn_ptr, const char *contact_token);
UFSRVResult *BackendDirectoryContactTokenDel (Session *sesn_ptr, const char *contact_token);
int BackEndDeleteNonce (Session *, const char *nonce, const char *prefix);
bool IsNonceValid(Session *sesn_ptr, const char *nonce, const char *prefix);
int BackEndGetNonce (Session *sesn_ptr_carrier, const char *nonce,  const char *prefix);
char *BackEndGenerateNonce (Session *, time_t expiry_in, const char *, const char *);
enum AccountRegoStatus GetAccountRegisterationStatus(Session *sesn_ptr, const char *username);

UFSRVResult *DbAccountGetE164Number (Session *sesn_ptr, unsigned long userid);
int DbAccountSetE164Number (Session *sesn_ptr, unsigned long userid, const char *e164number);
UFSRVResult *DbValidateUserId (Session *sesn_ptr, unsigned long userid);
bool IsUserIdValid (Session *sesn_ptr, unsigned long userid);
UFSRVResult *DbValidateUserSignOnWithCookie (Session *, const char *, AuthenticatedAccount *acct_ptr, UFSRVResult *);
UFSRVResult *DbAuthenticateUser (Session *sesn_ptr, unsigned long, char *password, const char *cookie, unsigned);
size_t (*GetDefaultBackendResponse()) (void *,size_t, size_t, void *);

const char *GetAccountAttributeForCloudMessaging (json_object *jobj_account, unsigned int device_id);
ProfileKeyStore *GetAccountAttributeForProfileKey (json_object *jobj_account, bool is_decoded, ProfileKeyStore *store_in);

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
UFSRVResult *DbAccountDataUserAttributeGetText (Session *sesn_ptr, unsigned long userid, const char *attribute_name);
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
struct json_object *DbGetAccountInJson (Session *sesn_ptr, const UfsrvUid *);
struct json_object *DbGetAccountUserDataInJson (Session *sesn_ptr, const UfsrvUid *uid_ptr);
struct json_object *DbGetAccountDataInJson (Session *sesn_ptr, const char *data_store, unsigned long);
struct json_object *DbGetAccountDataInJsonByUserId (Session *sesn_ptr, const char *data_store, unsigned long userid);
struct json_object *DbGetAccountInJsonByUserId (Session *sesn_ptr, unsigned long userid);
struct json_object *DbGetAccountUserDataInJsonByUserId (Session *sesn_ptr, unsigned long userid);

const char *DbBackendGetProfileKey(Session *sesn_ptr, const UfsrvUid *, bool is_encoded);
UFSRVResult *DbBackendSetProfileKey (Session *sesn_ptr, const char *profile_key_encoded);
UFSRVResult *DbBackendSetProfileKeyIfNecessary (Session *sesn_ptr, const char *profile_key_encoded, bool is_force_update);
const char *DbBackendGetAccessToken(Session *sesn_ptr, const UfsrvUid *, bool is_encoded);
UFSRVResult *DbBackendSetAccessToken (Session *sesn_ptr, const char *profile_key_encoded);
UFSRVResult *DbBackendSetAccessTokenIfNecessary (Session *sesn_ptr, const char *access_token_encoded, bool is_force_update);

UFSRVResult *BackendDirectoryNicknameSet (Session *sesn_ptr, const char *nickname);
UFSRVResult *BackendDirectoryNicknameGet (Session *sesn_ptr, const char *nickname);
UFSRVResult *BackendDirectoryNicknameDel (Session *sesn_ptr, const char *);
bool IsNicknameAvailable (Session *sesn_ptr, const char *nickname);
UFSRVResult *AccountNicknameValidateForUniqueness(Session *sesn_ptr, const UfsrvUid *, const char *nickname_by_user);

#endif /* SRC_INCLUDE_USER_BACKEND_H_ */
