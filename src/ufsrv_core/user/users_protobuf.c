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
#include <nportredird.h>
#include <ufsrv_core/fence/fence_protobuf.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/user/users.h>
#include <session.h>
#include <ufsrvuid.h>
#include <utils_crypto.h>
#include <utils_curve.h>

inline static void _PopulateUserDetails (const Session *sesn_ptr, UserRecord *user_rec_ptr, bool, bool);
inline static void _PopulateUfsrvUidForUserRecord (Session *sesn_ptr, UfsrvUidRequesterDescriptor *ufsrvuid_request_ptr, UserRecord *user_rec_ptr);

extern ufsrv							*const masterptr;

/**
 *  @param sesn_ptr: session from where user data is read
 * 	@param flag_ref_mode:	if set, use by ref where possible as opposed to duplicating values
 */
inline static void
_PopulateUserDetails (const Session *sesn_ptr, UserRecord *user_rec_ptr, bool flag_digest_mode, bool flag_ref_mode)
{
	user_rec_ptr->username	=	flag_ref_mode?(SESSION_USERNAME(sesn_ptr)):(strdup(SESSION_USERNAME(sesn_ptr)));

	MakeUfsrvUidInProto((UfsrvUid *)&SESSION_UFSRVUIDSTORE(sesn_ptr), &(user_rec_ptr->ufsrvuid), true);
	user_rec_ptr->eid = SESSION_EID(sesn_ptr); user_rec_ptr->has_eid = 1;

	if (flag_digest_mode == PROTO_USER_RECORD_MINIMAL)	return;

	//urec_ptr_aux->location=calloc(1, sizeof(LocationRecord));

	//TODO enable user lookup
	//location_record__init(urec_ptr_aux->location);
	//urec_ptr_aux->location->longitude=USER_LONGITUDE;
	//urec_ptr_aux->location->latitude=USER_LATITUDE;
	//urec_ptr_aux->location->locality=strdup(USER_LOCALITY);

}

/**
 * @brief Minimalist UserRecord based on sequence userid
 * @param sesn_ptr_carrier carrier Session for backend access context
 * @param ufsrvuid_request_ptr
 * @param user_rec_ptr preallocated UserRecord to save into
 * @dynamic_memory: ALLOCATES 'unsigned char *' into UserRecord when 'flag_by_ref' is set true in calling MakeUfsrvUidInProto()
 */
inline static void
_PopulateUfsrvUidForUserRecord (Session *sesn_ptr_carrier, UfsrvUidRequesterDescriptor *ufsrvuid_request_ptr, UserRecord *user_rec_ptr)
{
	if (IS_PRESENT(GetUfsrvUid(sesn_ptr_carrier, ufsrvuid_request_ptr->uid, &(ufsrvuid_request_ptr->ufsrvuid), false, NULL))) {
    MakeUfsrvUidInProto(&(ufsrvuid_request_ptr->ufsrvuid), &(user_rec_ptr->ufsrvuid), false);
  }
	user_rec_ptr->username = "*"; //this not needed

}

UserRecord *
MakeUserRecordFromUseridInProto (Session *sesn_ptr_carrier, unsigned long userid, UserRecord *user_record_supplied)
{
	UfsrvUidRequesterDescriptor ufsrvuid_request 	=	{.uid=userid, .ufsrvuid={{0}}};
	UserRecord									*user_record_ptr	=	NULL;

	if (IS_PRESENT(user_record_supplied))	user_record_ptr=user_record_supplied;
	else	user_record_ptr = calloc(1, sizeof(UserRecord));

	user_record__init(user_record_ptr);

	_PopulateUfsrvUidForUserRecord(sesn_ptr_carrier, &ufsrvuid_request, user_record_ptr);

	return user_record_ptr;
}

/**
 * 	@brief: Instantiates user session if necessary from backend. In this case, it will be hashed and deallocated separately
 * 	@param sesn_ptr: connected session context or ephemeral
 * 	@dynamic_memory: EXPORST UserRecord * which the user is responsible for freeing
 */
UserRecord *
MakeUserRecordFromUsernameInProto (Session *sesn_ptr, const char *username, UserRecord *user_record_supplied, bool flag_digest_mode)
{
	if (unlikely((IS_EMPTY(sesn_ptr)) || (IS_EMPTY(username))))	return NULL;

	Session *sesn_ptr_target_user = NULL;

	unsigned long call_flags = 0;
	call_flags |= (CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY);//|CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION);//WE ARE NOT LOCKING SESSION

	__unused bool lock_already_owned = false;
	GetSessionForThisUser(sesn_ptr, (char *)username, &lock_already_owned, call_flags);
	sesn_ptr_target_user = SessionOffInstanceHolder((InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr));

	if (IS_PRESENT(sesn_ptr_target_user)) {
		if (CALLGFLAG_IS_SET(sesn_ptr_target_user->stat, SESNSTATUS_UNDERCONSTRUCTION)) {
			//todo: is this likely to happen?
		}

		//IMPORTANT SESSION NOT LOCKED SO THIS IS READONLY
		UserRecord	*user_record_ptr = NULL;
		if (IS_PRESENT(user_record_supplied))	user_record_ptr = user_record_supplied;
		else	user_record_ptr = calloc(1, sizeof(UserRecord));

		user_record__init(user_record_ptr);

		_PopulateUserDetails(sesn_ptr_target_user, user_record_ptr, flag_digest_mode, false);

		return user_record_ptr;
	}

	return NULL;
}

/**
 * 	@brief: Initialiase and populate user details based on provided Session object.
 *
 */
UserRecord *
MakeUserRecordFromSessionInProto (Session *sesn_ptr_source, UserRecord *user_record_supplied, bool flag_digest_mode, bool flag_ref_mode)
{
	//IMPORTANT SESSION UNLOCKED SO THIS IS READ-ONLY
	UserRecord	*user_record_ptr = NULL;
	if (IS_PRESENT(user_record_supplied))	user_record_ptr = user_record_supplied;
	else	user_record_ptr = calloc(1, sizeof(UserRecord));

	user_record__init(user_record_ptr);

	_PopulateUserDetails(sesn_ptr_source, user_record_ptr, flag_digest_mode, flag_ref_mode);

	return user_record_ptr;
}

/**
 * 	@brief: construct for this session owner
 */
UserRecord *
MakeUserRecordForSelfInProto (const Session *sesn_ptr, bool flag_digest_mode)
{
	//IMPORTANT SESSION MAY OR MAY NOT BE LOCKED
	UserRecord	*user_record_ptr = calloc(1, sizeof(UserRecord));
	user_record__init(user_record_ptr);

	_PopulateUserDetails(sesn_ptr, user_record_ptr, flag_digest_mode, false);

	return user_record_ptr;
}

void
DestructUserInfoInProto (UserRecord *user_record_ptr, bool flag_self_destruct)
{
	if (unlikely(IS_EMPTY(user_record_ptr)))	return;

	if (IS_PRESENT(user_record_ptr->username))	{free(user_record_ptr->username); user_record_ptr->username = NULL;}
	if (IS_PRESENT(user_record_ptr->avatar)) DestructAttachmentRecord(user_record_ptr->avatar, true);

	if (flag_self_destruct == true) {
		free(user_record_ptr);
		LOAD_NULL(user_record_ptr);
	}

}

/**
 * 	@param collection_ptr_out: if present must be fully allocated including collection_ptr_out->collection
 * 	@return: on emptyset, NUL is returned for collection
 *
 */
CollectionDescriptor *
MakeSessionMessageUserPreferenceInProto (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr, CollectionDescriptor *collection_ptr_out)
{
	if (pref_collection_ptr->collection_sz==0)	return NULL;

	void 														*msgpref_pool;
	CollectionDescriptor						*collection_ptr=NULL;
	UserPreference 	*msgpref_ptr=NULL;
	UserPreference **msgprefs_ptr=NULL;

	if (IS_PRESENT(collection_ptr_out))
	{
		collection_ptr=collection_ptr_out;
	}
	else
	{
		collection_ptr=calloc(1, sizeof(CollectionDescriptor));
		collection_ptr->collection=calloc(pref_collection_ptr->collection_sz, sizeof(UserPreference *));
		msgpref_pool=calloc(pref_collection_ptr->collection_sz, sizeof(UserPreference));//one chunk
	}

	size_t processed_sz=0;
	for (size_t i=0; i<pref_collection_ptr->collection_sz; i++)
	{
		UserPreferenceDescriptor *pref_descriptor_ptr=(UserPreferenceDescriptor *)pref_collection_ptr->collection[i];

		if (likely(IS_PRESENT(collection_ptr_out)))
		{
			msgpref_ptr=(UserPreference *)collection_ptr->collection[i];
		}
		else
		{
			msgpref_ptr=(UserPreference *)(msgpref_pool+(processed_sz*sizeof(UserPreference)));
		}


		user_preference__init(msgpref_ptr);

		msgpref_ptr->pref_id=pref_descriptor_ptr->pref_id;
		msgpref_ptr->type=pref_descriptor_ptr->pref_value_type;
		//msgpref_ptr->pref_name=GetPrefNameByIndex(msgpref_ptr->pref_id); //the possibility is there...

		if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_BOOL)
		{
			msgpref_ptr->values_int=pref_descriptor_ptr->value.pref_value_bool;	msgpref_ptr->has_values_int=1;
		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_INT)
		{
			msgpref_ptr->values_int=pref_descriptor_ptr->value.pref_value_int;	msgpref_ptr->has_values_int=1;
		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_STR)
		{
			msgpref_ptr->values_str=strdup(pref_descriptor_ptr->value.pref_value_str);
		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_STR_MULTI)
		{

		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_INT_MULTI)
		{

		}
		else
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', value_type:'%d'}: ERROR: WRONG PREF VAUE TYPE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), pref_descriptor_ptr->pref_value_type);
			continue;
		}

		processed_sz++;
	}

	if (processed_sz==0)
	{
		if (IS_EMPTY(collection_ptr_out)) {free (collection_ptr->collection); free(collection_ptr); free(msgpref_pool);}

		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', processed_sz:'%lu'}: ERROR: EMPTYSET POST PROCESSING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), processed_sz);

		return NULL;
	}


	collection_ptr->collection_sz	=	processed_sz;

	return collection_ptr;
}

#if 0
//Not clear if seperate semantics needed for FenceUserPreference other than defined in  MakeSessionMessageUserPreferenceInProto
/**
 * 	@brief: Format provided user prefs for a given fence in proto
 * 	@param fences_collection_ptr: collecton of fences
 * 	@param pref_collection_ptr: collection of prefs
 * 	@param collection_ptr_out: if present must be fully allocated including collection_ptr_out->collection
 * 	@return: on emptyset, NUL is returned for collection
 *
 */
CollectionDescriptor *
MakeSessionMessageFenceUserPreferenceInProto (PairedSessionFenceState *paired_ptr, CollectionDescriptor *pref_collection_ptr, CollectionDescriptor *collection_ptr_out)
{
	if (pref_collection_ptr->collection_sz==0)	return NULL;

	void 														*msgpref_pool;
	Session													*sesn_ptr				=	paired_ptr->session_ptr;
	CollectionDescriptor						*collection_ptr	=	NULL;
	UserPreference 	*msgpref_ptr		=	NULL;
	UserPreference **msgprefs_ptr		=	NULL;
//	SessionMessage__FenceUserPreference 	*msgfpref_ptr		=	NULL;
//	SessionMessage__FenceUserPreference **msgfprefs_ptr		=	NULL;

	if (IS_PRESENT(collection_ptr_out))
	{
		collection_ptr=collection_ptr_out;
	}
	else
	{
		collection_ptr=calloc(1, sizeof(CollectionDescriptor));
		collection_ptr->collection=calloc(pref_collection_ptr->collection_sz, sizeof(UserPreference *));
		msgpref_pool=calloc(pref_collection_ptr->collection_sz, sizeof(UserPreference));//one chunk
	}

	size_t processed_sz=0;
	for (size_t i=0; i<pref_collection_ptr->collection_sz; i++)
	{
		UserPreferenceDescriptor *pref_descriptor_ptr=(UserPreferenceDescriptor *)pref_collection_ptr->collection[i];

		if (likely(IS_PRESENT(collection_ptr_out)))
		{
			msgpref_ptr=(UserPreference *)collection_ptr->collection[i];
		}
		else
		{
			msgpref_ptr=(UserPreference *)(msgpref_pool+(processed_sz*sizeof(UserPreference)));
		}


		session_message__user_preference__init(msgpref_ptr);

		msgpref_ptr->pref_id=pref_descriptor_ptr->pref_id;
		msgpref_ptr->type=pref_descriptor_ptr->pref_value_type;
		//msgpref_ptr->pref_name=GetPrefNameByIndex(msgpref_ptr->pref_id); //the possibility is there...

		if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_BOOL)
		{
			msgpref_ptr->values_int=pref_descriptor_ptr->value.pref_value_bool;	msgpref_ptr->has_values_int=1;
		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_INT)
		{
			msgpref_ptr->values_int=pref_descriptor_ptr->value.pref_value_int;	msgpref_ptr->has_values_int=1;
		}
		else if (pref_descriptor_ptr->pref_value_type==PREFVALUETYPE_STR)
		{
			msgpref_ptr->values_str=strdup(pref_descriptor_ptr->value.pref_value_str);
		}
		else
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', value_type:'%d'}: ERROR: WRONG PREF VAUE TYPE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), pref_descriptor_ptr->pref_value_type);
			continue;
		}

		processed_sz++;
	}

	if (processed_sz==0)
	{
		if (IS_EMPTY(collection_ptr_out)) {free (collection_ptr->collection); free(collection_ptr); free(msgpref_pool);}

		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', processed_sz:'%lu'}: ERROR: EMPTYSET POST PROCESSING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), processed_sz);

		return NULL;
	}


	collection_ptr->collection_sz	=	processed_sz;

	return collection_ptr;
}
#endif

/**
 * 	@brief: Adapt the wire data model for userPreferences to local UserreferenceDescripto
 */
__attribute__ ((const)) CollectionDescriptor *
LoadUserPreferenceBySessionMessageProto (MessageQueueMessage *mqm_ptr, CollectionDescriptor *collection_prefs_out)
{
	for (size_t i=0; i<mqm_ptr->session->n_prefs; i++)
	{
		UserPreference 						*sesnmsg_pref_ptr	=	mqm_ptr->session->prefs[i];
		UserPreferenceDescriptor 	*userpref_ptr			=	(UserPreferenceDescriptor *)collection_prefs_out->collection[i];

		userpref_ptr->pref_id   = sesnmsg_pref_ptr->pref_id;
		userpref_ptr->pref_name = sesnmsg_pref_ptr->pref_name;

		switch (sesnmsg_pref_ptr->type)
		{
			case PREFERENCE_TYPE__BOOL:
				userpref_ptr->pref_value_type=PREFVALUETYPE_BOOL;
				userpref_ptr->value.pref_value_bool=sesnmsg_pref_ptr->values_int;
				break;

			case PREFERENCE_TYPE__INT:
				//todo
				//this maybe multi value read off: sesnmsg_pref_ptr->n_values_int_m
				userpref_ptr->pref_value_type       = PREFVALUETYPE_INT;
				userpref_ptr->value.pref_value_int  = sesnmsg_pref_ptr->values_int;

				break;

			case PREFERENCE_TYPE__STR:
				//todo
				//this maybe multi value read off: sesnmsg_pref_ptr->n_values_str_m
				userpref_ptr->pref_value_type       = PREFVALUETYPE_STR;
				userpref_ptr->value.pref_value_str  = sesnmsg_pref_ptr->values_str;//TODO: WATCH OUT FOR STRING DISAPPEARING FROM SCOPE
				break;

			default:
				syslog(LOG_DEBUG, "%s {pid:'%lu', value_type:'%d'}: ERROR: WRONG PREF VAUE TYPE...", __func__, pthread_self(), sesnmsg_pref_ptr->type);
				return NULL;

		}
	}

	return collection_prefs_out;
}

//UserCommand__ShareType

/*
 * 	@brief: uses computed goto
 */
const UserPreferenceDescriptor *
MapShareListTypeToUserPref (UserCommand__ShareType share_type)
{
	//Align with defined enum EnumShareListType
	static void *type_table[] = {
			&&type_profile, &&type_location, &&type_contact, &&type_netstate
	};

	goto *type_table[share_type];

	type_profile:		return GetPrefDescriptorById(PREF_SHLIST_PROFILE);
	type_location: 	return GetPrefDescriptorById(PREF_SHLIST_LOCATION);
	type_contact: 	return GetPrefDescriptorById(PREF_SHLIST_CONTACTS);
	type_netstate: 	return GetPrefDescriptorById(PREF_SHLIST_NETSTATE);
}

/**
 *
 * @param uid_ptr source userid
 * @param proto_ptr target userid in protobuf
 * @param flag_by_ref if set reassign uid buffer by reference
 * @dynamic_memory: EXPORTS
 */
void
MakeUfsrvUidInProto(UfsrvUid *uid_ptr, ProtobufCBinaryData *proto_ptr, bool flag_by_ref)
{
  proto_ptr->len  = CONFIG_MAX_UFSRV_ID_SZ;
	if (flag_by_ref) {
    proto_ptr->data = uid_ptr->data;
	} else {
    proto_ptr->data = calloc(CONFIG_MAX_UFSRV_ID_SZ, sizeof(uint8_t));
    memcpy(proto_ptr->data, uid_ptr->data, CONFIG_MAX_UFSRV_ID_SZ);
  }
}

UFSRVResult *
MakeIdentityCertificate (Session *sesn_ptr, IdentityCertificate *cert_identity_ptr, ServerCertificate *cert_server_ptr)
{
  DbAccountIdentityKeyGet (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), 0);
  if (unlikely(IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)))) {
    goto error_identity_key;
  }

  char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
  UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr), ufsrvuid_encoded);
  const unsigned char *identity_key = SESSION_RESULT_USERDATA(sesn_ptr);
  cert_identity_ptr->identitykey.data     = base64_decode(identity_key, strlen((const char *)identity_key),  (int *)&(cert_identity_ptr->identitykey.len));
  cert_identity_ptr->has_identitykey      = 1;
  cert_identity_ptr->sender               = ufsrvuid_encoded;
  cert_identity_ptr->senderdevice         = 0; cert_identity_ptr->has_senderdevice =1;
  cert_identity_ptr->expires              = GetTimeNowInMillis()+_CONFIG_SENDER_CERTIFICATE_EXPIRYTIME; //1 day
  cert_identity_ptr->has_expires          = 1;
  cert_identity_ptr->signer               = cert_server_ptr;
  SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_NONE)

  error_identity_key:
  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * Assemble a completed SenderCertificate. The user must allocate the SenderCertificateContext
 * @param sesn_ptr Must correspond with the user for which the sender certificate is being prepared
 * @param cert_ctx_ptr All necessary structures allocated
 * @return
 * @dynamic_memory: EXPORTS protobuffer binary data
 * @dynamic_memory: EXPORTS data_buffer from signature calculation. must be offset by '- sizeof(data_buffer)' to free actual malloced pointer
 */
UFSRVResult *
MakeSenderCertificate (Session *sesn_ptr, SenderCertificateContext *cert_ctx_ptr)
{
  if (GetSignedCertificate(&(MASTER_CONF_SERVER_PRIVATEKEY), &(MASTER_CONF_SERVER_PUBLICKEY), cert_ctx_ptr->cert_server_ptr, cert_ctx_ptr->cert_key_ptr, SERVER_KEYID)) {
    SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, RESULT_CODE_NONE)
  }

  MakeIdentityCertificate (sesn_ptr, cert_ctx_ptr->cert_identity_ptr, cert_ctx_ptr->cert_server_ptr);
  if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
    return SESSION_RESULT_PTR(sesn_ptr);
  }

  size_t certificate_packed_sz=identity_certificate__get_packed_size(cert_ctx_ptr->cert_identity_ptr);
  uint8_t *certificate_packed = calloc(1, certificate_packed_sz);
  identity_certificate__pack(cert_ctx_ptr->cert_identity_ptr, certificate_packed);

  data_buffer *cert_key_signature = 0;
  int result = curve_calculate_signature(&cert_key_signature, &(MASTER_CONF_SERVER_PRIVATEKEY), certificate_packed, certificate_packed_sz);
  if (result != 0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR COULD NOT CALCULATE SIGNATURE", __func__, pthread_self());
    goto error_key_cert;
  }

  cert_ctx_ptr->cert_sender_ptr->certificate.data = certificate_packed;
  cert_ctx_ptr->cert_sender_ptr->certificate.len  = certificate_packed_sz;
  cert_ctx_ptr->cert_sender_ptr->signature.data   = cert_key_signature->data;
  cert_ctx_ptr->cert_sender_ptr->signature.len    = cert_key_signature->len;
  cert_ctx_ptr->cert_sender_ptr->has_signature    = cert_ctx_ptr->cert_sender_ptr->has_certificate
                                                  = 1;
  SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_NONE)

  error_key_cert:
  SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, RESULT_CODE_NONE)
}

__attribute__((const)) bool
IsProtoUfsrvUidDefined (const ProtobufCBinaryData *ufsrvuid)
{
  if (IS_PRESENT(ufsrvuid) && IS_PRESENT(ufsrvuid->data) && ufsrvuid->len == CONFIG_MAX_UFSRV_ID_SZ) return true;

  return false;
}