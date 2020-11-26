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
#include <attachments.h>
#include <ufsrv_core/fence/fence_protobuf.h>
#include <fence_proto.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/user/user_type.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
#include <nportredird.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/fence/fence_permission.h>
#include <recycler/recycler.h>

extern __thread ThreadContext ufsrv_thread_context;

void
MakeFenceAvatarInProto (Session *sesn_ptr_carrier, FenceRecord *fence_record,  const char *avatar_id, AttachmentDescriptor *attachment_descriptor_ptr_out, AttachmentRecord *attachment_record_ptr_out)
{
	if (unlikely(IS_EMPTY(avatar_id)))	return;

	bool									is_provided_descriptor = false;
	AttachmentRecord 			*attachment_record_ptr;
	AttachmentDescriptor 	*attachment_descriptor_ptr;

	if (IS_PRESENT(attachment_descriptor_ptr_out))	{attachment_descriptor_ptr = attachment_descriptor_ptr_out; is_provided_descriptor = true;}
	else 																						attachment_descriptor_ptr = calloc(1, sizeof(AttachmentDescriptor));

	if (IS_PRESENT(attachment_record_ptr_out))	{attachment_record_ptr = attachment_record_ptr_out;}
	else 																				attachment_record_ptr = calloc(1, sizeof(AttachmentRecord));

	if (IS_PRESENT((attachment_descriptor_ptr=GetAttachmentDescriptorEphemeral (sesn_ptr_carrier, avatar_id, true, attachment_descriptor_ptr)))) {
		MakeAttachmentRecordInProto(attachment_descriptor_ptr, attachment_record_ptr, true);//dupping attachment_descriptor_ptr fields because there is no way to deallocate it further upstream
		fence_record->avatar		=	attachment_record_ptr;
		AttachmentDescriptorDestruct (attachment_descriptor_ptr, true, !is_provided_descriptor);
	}
}

void
MakeFenceListSemanticsInProto (Fence *f_ptr, FenceRecord *fence_record_ptr)
{
	if (FENCE_PERMISSIONS_PRESENTATION(f_ptr).config.whitelist)	fence_record_ptr->presentation->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST;
	else fence_record_ptr->presentation->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
	fence_record_ptr->presentation->has_list_semantics=1;

	if (FENCE_PERMISSIONS_MEMBERSHIP(f_ptr).config.whitelist)	fence_record_ptr->membership->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST;
	else fence_record_ptr->membership->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
	fence_record_ptr->membership->has_list_semantics=1;

	if (FENCE_PERMISSIONS_MESSAGING(f_ptr).config.whitelist)	fence_record_ptr->messaging->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST;
	else fence_record_ptr->messaging->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
	fence_record_ptr->messaging->has_list_semantics=1;

	if (FENCE_PERMISSIONS_ATTACHING(f_ptr).config.whitelist)	fence_record_ptr->attaching->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST;
	else fence_record_ptr->attaching->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
	fence_record_ptr->attaching->has_list_semantics=1;

	if (FENCE_PERMISSIONS_CALLING(f_ptr).config.whitelist)	fence_record_ptr->calling->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST;
	else fence_record_ptr->calling->list_semantics=FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
	fence_record_ptr->calling->has_list_semantics=1;

}

static void _MakeFencePermissionsUserListsInProto(Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr, FenceRecord__Permission *fence_record_permission);

void
MakeFencePermissionsUserListsInProto (Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr)
{
  _MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, FENCE_PERMISSIONS_PRESENTATION_PTR(f_ptr), fence_record_ptr->presentation);
  _MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr), fence_record_ptr->membership);
  _MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, FENCE_PERMISSIONS_MESSAGING_PTR(f_ptr), fence_record_ptr->messaging);
  _MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, FENCE_PERMISSIONS_ATTACHING_PTR(f_ptr), fence_record_ptr->attaching);
  _MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, FENCE_PERMISSIONS_CALLING_PTR(f_ptr), fence_record_ptr->calling);

}

typedef struct PermissionProtoBuilderExecutorContext {
  size_t *index;
  UserRecord *user_record;
  UserRecord **user_records;
} PermissionProtoBuilderExecutorContext;

static UFSRVResult *_LoadPermissionList (PermissionProtoBuilderExecutorContext *ctx_ptr, ClientContextData  *userid_container);

static UFSRVResult *
_LoadPermissionList (PermissionProtoBuilderExecutorContext *ctx_ptr, ClientContextData  *userid_container)
{
#if __VALGRIND_DRD
	VALGRIND_MEMPOOL_ALLOC(ctx_ptr->user_records, ctx_ptr->user_records + *ctx_ptr->index, sizeof(UserRecord *));
	VALGRIND_MEMPOOL_ALLOC(ctx_ptr->user_record, (ctx_ptr->user_record + (*ctx_ptr->index * sizeof(UserRecord))), sizeof(UserRecord));
#endif
	//userid_container+CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id);
	Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)userid_container);
	UserRecord *urec_ptr_aux2[1];
	urec_ptr_aux2[0] = (UserRecord *)(ctx_ptr->user_record + (*ctx_ptr->index++ * sizeof(UserRecord)));//chunk up vector as needed
	UserRecord *user_record_ptr = urec_ptr_aux2[0];

  user_record__init(user_record_ptr);
//  user_record_ptr->userid = SESSION_USERID(sesn_ptr); user_record_ptr->has_userid = 1;
	MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(user_record_ptr->ufsrvuid), true);

  SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_NONE)
}

static void
_MakeFencePermissionsUserListsInProto(Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr, FenceRecord__Permission *fence_record_permission)
{
  _InitialiseStorageIfNecessary(sesn_ptr, f_ptr, permission_ptr);
  _InitialiseMembersIfNecessary(sesn_ptr, f_ptr, permission_ptr);
  size_t iterator_index = 0;

  size_t allocated_size = GetHopscotchHashtableAllocatedSize(&permission_ptr->permitted_users);
  UserRecord **user_records;
	void 				*user_record;

	user_records = calloc(allocated_size, sizeof(UserRecord *));
	user_record = calloc(allocated_size, sizeof(UserRecord));

#if __VALGRIND_DRD
	VALGRIND_CREATE_MEMPOOL(user_records, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_records, allocated_size*(sizeof(UserRecord *)));

	VALGRIND_CREATE_MEMPOOL(user_record, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_record, allocated_size*(sizeof(UserRecord)));
#endif

  PermissionProtoBuilderExecutorContext ctx = {&iterator_index, user_record, user_records };

  hopscotch_iterator_executor(&permission_ptr->permitted_users, (CallbackExecutor)_LoadPermissionList, CLIENT_CTX_DATA(&ctx));

  if (iterator_index == 0) {
  	free (user_records);
  	free (user_record);
		fence_record_permission->users = NULL;//propably not necessary
#if __VALGRIND_DRD
		VALGRIND_DESTROY_MEMPOOL(user_records);
		VALGRIND_DESTROY_MEMPOOL(user_record);
#endif
  } else {
		fence_record_permission->users = user_records;
		fence_record_permission->n_users = iterator_index;
	}
}
void
MakeFencePermissionsInProto(Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr)
{

	void *ptr=calloc(5, sizeof(FenceRecord__Permission));
	fence_record_ptr->presentation=ptr; ptr+=sizeof(FenceRecord__Permission);
	fence_record_ptr->membership=ptr; ptr+=sizeof(FenceRecord__Permission);
	fence_record_ptr->messaging=ptr; ptr+=sizeof(FenceRecord__Permission);
	fence_record_ptr->attaching=ptr; ptr+=sizeof(FenceRecord__Permission);
	fence_record_ptr->calling=ptr;

	fence_record__permission__init(fence_record_ptr->presentation);
	fence_record__permission__init(fence_record_ptr->membership);
	fence_record__permission__init(fence_record_ptr->messaging);
	fence_record__permission__init(fence_record_ptr->attaching);
	fence_record__permission__init(fence_record_ptr->calling);

	fence_record_ptr->presentation->type=FENCE_RECORD__PERMISSION__TYPE__PRESENTATION;
	fence_record_ptr->membership->type=FENCE_RECORD__PERMISSION__TYPE__MEMBERSHIP;
	fence_record_ptr->messaging->type=FENCE_RECORD__PERMISSION__TYPE__MESSAGING;
	fence_record_ptr->attaching->type=FENCE_RECORD__PERMISSION__TYPE__ATTACHING;
	fence_record_ptr->calling->type=FENCE_RECORD__PERMISSION__TYPE__CALLING;

	MakeFenceListSemanticsInProto (f_ptr, fence_record_ptr);
  MakeFencePermissionsUserListsInProto (sesn_ptr, f_ptr, fence_record_ptr);

}

#include <ufsrv_core/fence/fence_state.h> //for FPREF_LAST_ALIGNMENT
static inline FenceUserPreference * _MakeFenceUserPreferenceInProto (FenceUserPreference *user_pref_ptr, FenceStateDescriptor *fstate_ptr, FenceUserPrefsOffsets pref_offset);

void
MakeFenceUserPreferencesInProto(Session *sesn_ptr, FenceStateDescriptor *fstate_ptr, FenceRecord *fence_record_ptr)
{
	FenceUserPreference **fence_preferences = calloc(FPREF_LAST_ALIGNMENT, sizeof(FenceUserPreference *));
  void *ptr = calloc(FPREF_LAST_ALIGNMENT, sizeof(FenceUserPreference));
  fence_record_ptr->n_fence_preferences = FPREF_LAST_ALIGNMENT;
	fence_record_ptr->fence_preferences = fence_preferences;

//	FenceUserPreference 	*urec_ptr_aux2[1];
	FenceUserPreference 	*urec_ptr_aux;

	//MAIN order as per enum
	urec_ptr_aux = _MakeFenceUserPreferenceInProto((FenceUserPreference *)(ptr + (PREF_STICKY_GEOGROUP * sizeof(FenceUserPreference))), fstate_ptr, PREF_STICKY_GEOGROUP);
//	urec_ptr_aux2[0]=(FenceUserPreference *)(ptr+(PREF_STICKY_GEOGROUP*sizeof(FenceUserPreference)));//chunk up vector as needed
//	urec_ptr_aux=urec_ptr_aux2[0];
//	fence_user_preference__init(urec_ptr_aux);
	fence_preferences[PREF_STICKY_GEOGROUP] = urec_ptr_aux;

//	urec_ptr_aux2[0]=(FenceUserPreference *)(ptr+(PREF_PROFILE_SHARING*sizeof(FenceUserPreference)));//chunk up vector as needed
//	urec_ptr_aux=urec_ptr_aux2[0];
//	fence_user_preference__init(urec_ptr_aux);
	urec_ptr_aux = _MakeFenceUserPreferenceInProto((FenceUserPreference *)(ptr + (PREF_PROFILE_SHARING * sizeof(FenceUserPreference))), fstate_ptr, PREF_PROFILE_SHARING);
	fence_preferences[PREF_PROFILE_SHARING] = urec_ptr_aux;

}

/**
 *  Currently only handles booleans
 * @param user_pref_ptr
 * @param fstate_ptr
 * @param pref_offset
 * @return
 */
static inline FenceUserPreference *
_MakeFenceUserPreferenceInProto (FenceUserPreference *user_pref_ptr, FenceStateDescriptor *fstate_ptr, FenceUserPrefsOffsets pref_offset)
{
	FenceUserPreference 	*urec_ptr_aux2[1];
	FenceUserPreference 	*urec_ptr_aux;

	urec_ptr_aux2[0] = user_pref_ptr;
	urec_ptr_aux = urec_ptr_aux2[0];
	fence_user_preference__init(urec_ptr_aux);

	urec_ptr_aux->pref_id = pref_offset;
	urec_ptr_aux->values_int = IsFenceUserPreferenceSet(&((PairedSessionFenceState){fstate_ptr, NULL}), pref_offset);
	urec_ptr_aux->has_values_int = 1;

	return urec_ptr_aux;
}

static void _DestructFencePermissionsUsersListInProto (FenceRecord__Permission *fence_record_permission);
static void
_DestructFencePermissionsUsersListInProto (FenceRecord__Permission *fence_record_permission)
{
	//space is calloc'ed as pool from which individual permissions are allocated
	if (IS_PRESENT(fence_record_permission) && IS_PRESENT(fence_record_permission->users)) {
		if (IS_PRESENT(fence_record_permission->users[0])) {
			free (fence_record_permission->users[0]);
#if __VALGRIND_DRD
			VALGRIND_DESTROY_MEMPOOL(fence_record_permission->users[0]);
#endif
			free (fence_record_permission->users);
#if __VALGRIND_DRD
			VALGRIND_DESTROY_MEMPOOL(fence_record_permission->users);
#endif
		}
	}
}

void
DestructFencePermissionsInProto (FenceRecord *fence_record_ptr)
{
	//space is calloc'ed as pool from which individual permissions are allocated
	if (IS_PRESENT(fence_record_ptr->presentation))
	{
		_DestructFencePermissionsUsersListInProto (fence_record_ptr->presentation);
		_DestructFencePermissionsUsersListInProto (fence_record_ptr->membership);
		_DestructFencePermissionsUsersListInProto (fence_record_ptr->messaging);
		_DestructFencePermissionsUsersListInProto (fence_record_ptr->attaching);
		_DestructFencePermissionsUsersListInProto (fence_record_ptr->calling);

		memset (fence_record_ptr->presentation, 0, 5*sizeof(FenceRecord__Permission));
		free (fence_record_ptr->presentation);
	}
}

void
DestructFenceUserPreferencesInProto (FenceRecord *fence_record_ptr) {
	if (IS_PRESENT(fence_record_ptr->fence_preferences)) {
		free (fence_record_ptr->fence_preferences[0]);
		fence_record_ptr->n_fence_preferences = 0;
	}
}

void
MakeFencePrivacyModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr)
{
	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_PRIVATE))	fence_record_ptr->privacy_mode=FENCE_RECORD__PRIVACY_MODE__PRIVATE;
	else 																							fence_record_ptr->privacy_mode=FENCE_RECORD__PRIVACY_MODE__PUBLIC;//default anyway

	fence_record_ptr->has_privacy_mode=1;
}

void
MakeFenceTypeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr)
{
	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE))	fence_record_ptr->fence_type=FENCE_RECORD__FENCE_TYPE__USER;
	else 																								fence_record_ptr->fence_type=FENCE_RECORD__FENCE_TYPE__GEO;

	fence_record_ptr->has_fence_type=1;
}

void
MakeFenceDeliveryModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr)
{
	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST))							fence_record_ptr->delivery_mode=FENCE_RECORD__DELIVERY_MODE__BROADCAST;
	else 	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY))	fence_record_ptr->delivery_mode=FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY;
	else if F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST)						fence_record_ptr->delivery_mode=FENCE_RECORD__DELIVERY_MODE__MANY;
	else fence_record_ptr->delivery_mode=FENCE_RECORD__DELIVERY_MODE__MANY; //defaulting

	fence_record_ptr->has_delivery_mode=1;
}

void
MakeFenceJoinModeInProto (Fence *f_ptr, FenceRecord *fence_record_ptr)
{
	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	fence_record_ptr->join_mode=FENCE_RECORD__JOIN_MODE__OPEN;
		else 																										fence_record_ptr->join_mode=FENCE_RECORD__JOIN_MODE__OPEN_WITH_KEY;
	}
	else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	fence_record_ptr->join_mode=FENCE_RECORD__JOIN_MODE__INVITE;
		else 																										fence_record_ptr->join_mode=FENCE_RECORD__JOIN_MODE__INVITE_WITH_KEY;
	}
	else	fence_record_ptr->join_mode=FENCE_RECORD__JOIN_MODE__OPEN; //defaults to open

	fence_record_ptr->has_join_mode=1;
}

/**
 * 	@brief: pulls together the various data model elements that make up a fence. Each element is an independent pointer
 * 	that gets destructued independently of this containing structure.
 * 	This does not process FenceStateDescriptor data. The use must invoke that seperately, depending on context
 */
FenceRecord *
MakeFenceRecordInProto (InstanceContextForSession *ctx_ptr, InstanceContextForFence *ctx_f_ptr, FenceRecord *fence_record_ptr_in)
{
	FenceRecord 								*fence_record_ptr	=NULL;
	FenceUserRecordsDescription *desc_ptr					=	NULL;
	AttachmentDescriptor				attach_descriptor	= {0};

	Fence *f_ptr = ctx_f_ptr->f_ptr;

	if (fence_record_ptr_in)	fence_record_ptr = fence_record_ptr_in;
	else 											fence_record_ptr = calloc(1, sizeof(FenceRecord));

	fence_record__init(fence_record_ptr);

	fence_record_ptr->fid					=	FENCE_ID(f_ptr); fence_record_ptr->has_fid=1;
  fence_record_ptr->eid					=	FENCE_FENECE_EVENTS_COUNTER(f_ptr); fence_record_ptr->has_eid=1;
	fence_record_ptr->fname				=	strdup(f_ptr->fence_location.display_banner_name);//if referenced directly it would be free the fences reference in Destructxx()
	fence_record_ptr->cname				=	strdup(f_ptr->fence_location.canonical_name);
	fence_record_ptr->usercount		=	FENCE_SESSIONS_LIST_SIZE(f_ptr); fence_record_ptr->has_usercount=1;
	fence_record_ptr->location		=	MakeFenceLocationInProto(f_ptr, true);

	UfsrvUid uid = {0};
  if (IS_PRESENT(GetUfsrvUid(ctx_ptr->sesn_ptr, FENCE_OWNER_UID(f_ptr), &(uid), false, NULL))) {
    MakeUfsrvUidInProto(&(uid), &(fence_record_ptr->owner_uid), false);
    fence_record_ptr->has_owner_uid = 1;
  }

  fence_record_ptr->expire_timer=	FENCE_MSG_EXPIRY(f_ptr); fence_record_ptr->has_expire_timer=1;
	fence_record_ptr->maxmembers	=	FENCE_MAX_MEMBERS(f_ptr);	fence_record_ptr->has_maxmembers=1;

	if (FENCE_MAX_MEMBERS(f_ptr) > 0)		{fence_record_ptr->maxmembers	=	FENCE_MAX_MEMBERS(f_ptr); fence_record_ptr->has_maxmembers	=	1;}
	MakeFencePrivacyModeInProto(f_ptr, fence_record_ptr);
	MakeFenceDeliveryModeInProto(f_ptr, fence_record_ptr);
	MakeFenceTypeInProto(f_ptr, fence_record_ptr);
	MakeFenceJoinModeInProto(f_ptr, fence_record_ptr);
  MakeFencePermissionsInProto(ctx_ptr->sesn_ptr, f_ptr, fence_record_ptr);
	if (IS_STR_LOADED(FENCE_AVATAR(f_ptr)))    MakeFenceAvatarInProto (ctx_ptr->sesn_ptr, fence_record_ptr, FENCE_AVATAR(f_ptr), &attach_descriptor, NULL);

	desc_ptr = MakeFenceMembersInProto(ctx_ptr,  ctx_f_ptr, CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE, 0);//dontlock fence
	if (desc_ptr) {
		if (desc_ptr->records_sz > 0) {
			fence_record_ptr->n_members = desc_ptr->records_sz;
			fence_record_ptr->members = desc_ptr->user_records;
		}

		free(desc_ptr);//contained objects are destructed separately in DestructFenceRecordProto()
	}

	desc_ptr = MakeFenceInviteListInProto(ctx_ptr->sesn_ptr, f_ptr, 0/*@call_flags: not locking fence*/);//fence should be setup with invite list by now
	if (desc_ptr) {
		if (desc_ptr->records_sz > 0) {
			fence_record_ptr->n_invited_members = desc_ptr->records_sz;
			fence_record_ptr->invited_members = desc_ptr->user_records;
		}

		free(desc_ptr);//contained objects are destructed separately in DestructFenceRecordProto()
	}

	return fence_record_ptr;

}

FenceRecord *
MakeFenceRecordInProtoAsIdentifier (Session *sesn_ptr, Fence *f_ptr, FenceRecord *fence_record_ptr_in)
{
	FenceRecord 				*fence_record_ptr = NULL;
	FenceUserRecordsDescription *desc_ptr = NULL;

	if (fence_record_ptr_in)	fence_record_ptr = fence_record_ptr_in;
	else 											fence_record_ptr = calloc(1, sizeof(FenceRecord));

	fence_record__init(fence_record_ptr);

	fence_record_ptr->fid = FENCE_ID(f_ptr); fence_record_ptr->has_fid = 1;

	return fence_record_ptr;

}

FenceRecord *
MakeFenceRecordInProtoAsIdentifierByParams (Session *sesn_ptr, unsigned long fid, FenceRecord *fence_record_ptr_in)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	return NULL;

	FenceRecord 				*fence_record_ptr=NULL;
	FenceUserRecordsDescription *desc_ptr=NULL;

	if (fence_record_ptr_in)	fence_record_ptr=fence_record_ptr_in;
	else
	{
		fence_record_ptr=calloc(1, sizeof(FenceRecord));
	}

	fence_record__init(fence_record_ptr);

	fence_record_ptr->fid=fid; fence_record_ptr->has_fid=1;

	return fence_record_ptr;

}

/**
 * 	@brief: similar to DestructUserRecordsProto, but different starting position.
 */
void
DestructFenceUserRecordsDescription (FenceUserRecordsDescription  *desc_ptr, bool flag_self_destruct)
{
	if (likely(desc_ptr!=NULL))
	{
		if (desc_ptr->records_sz>0)
		{
			UserRecord *user_rec_ptr=desc_ptr->user_records[0];

//enable when the vector allocation method stops segfaulting
#if 0
#if __VALGRIND_DRD
		VALGRIND_DESTROY_MEMPOOL(user_rec_ptr);
		VALGRIND_DESTROY_MEMPOOL(desc_ptr->user_records);
#endif
#endif
			free (user_rec_ptr);//one whole vector
			free (desc_ptr->user_records);
		}

		if (flag_self_destruct)
		{
			free (desc_ptr);
			desc_ptr=NULL;
		}
	}

}

/**
 * 	@brief: This contains two seperate allocations:
 * 	1)the array itself
 * 	2)the first element is a contiguous storage vector chunked-up per record per member
 */
void
DestructUserRecordsProto (UserRecord  **user_records_ptr, size_t members_sz, bool flag_self_destruct)
{
	if (likely(user_records_ptr!=NULL))
	{
		UserRecord *user_rec_ptr=user_records_ptr[0];


		//DestructUserInfoInProto (user_rec_ptr, false);
		free (user_rec_ptr);

#if __VALGRIND_DRD
				VALGRIND_DESTROY_MEMPOOL(user_rec_ptr);
#endif

		if (flag_self_destruct)
		{
			free (user_records_ptr);
#if __VALGRIND_DRD
		VALGRIND_DESTROY_MEMPOOL(user_records_ptr);
#endif
			user_records_ptr=NULL;
		}
	}

}

/**
 * 	@param FenceEvent **: indexed collection of 'FenceEvents *'. It may contain null elements.
 */
FenceUserRecordsDescription *
MakeFenceInviteListFromNamesInProto (Session *sesn_ptr, char **members_invited, size_t members_sz, unsigned call_flags)
{
#if 1
	//uses memory vector
	if (members_sz == 0) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', , size:'%lu'}: NOTICE: Received empty Invite Members List.", __func__, pthread_self(), sesn_ptr, members_sz);
#endif
		FenceUserRecordsDescription	*desc_ptr = NULL;

		desc_ptr = calloc(1, sizeof(FenceUserRecordsDescription));

		return desc_ptr;
	}

	UserRecord 					**user_records	    = NULL;
	void 						    *user_rec_ptr	      = NULL;
	FenceUserRecordsDescription	*desc_ptr		= NULL;

	desc_ptr = calloc(1, sizeof(FenceUserRecordsDescription));

	user_records = calloc(members_sz, sizeof(UserRecord *));//we may fill less than that if flag not set: CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE
	user_rec_ptr = calloc(members_sz, sizeof(UserRecord));

#if __VALGRIND_DRD
	VALGRIND_CREATE_MEMPOOL(user_records, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_records, members_sz*(sizeof(UserRecord *)));

	VALGRIND_CREATE_MEMPOOL(user_rec_ptr, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_rec_ptr, members_sz*(sizeof(UserRecord)));
#endif

	int 			i,
					processed_counter	= 0;
	UserRecord 		*urec_ptr_aux;
	UserRecord 		*urec_ptr_aux2[1];

	for (i = 0; i < members_sz; i++) {
#if __VALGRIND_DRD
		VALGRIND_MEMPOOL_ALLOC(user_records, user_records+processed_counter, sizeof(UserRecord *));
		VALGRIND_MEMPOOL_ALLOC(user_rec_ptr, user_rec_ptr+(processed_counter * sizeof(UserRecord)), sizeof(UserRecord));
#endif
		urec_ptr_aux2[0] = (UserRecord *)(user_rec_ptr + (processed_counter * sizeof(UserRecord)));//chunk up vector as needed
		urec_ptr_aux = urec_ptr_aux2[0];

		if (IS_OK(MakeUserRecordFromUsernameInProto(sesn_ptr, members_invited[i], urec_ptr_aux, PROTO_USER_RECORD_MINIMAL)))
			user_records[processed_counter] = urec_ptr_aux;//connect to the array
		else continue; //counter not incremented

		user_records[processed_counter] = urec_ptr_aux;//connect the record to the array

		processed_counter++;
	}//for

	if (processed_counter > 0)
	{
		desc_ptr->records_sz = processed_counter;
		desc_ptr->user_records = user_records;

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: FINISHED PROTO representation for Invited members list. User count '%lu'", __func__, pthread_self(), sesn_ptr, desc_ptr->records_sz);
#endif

		return desc_ptr;
	} else {
		free(user_rec_ptr);
		free (user_records);
		free(desc_ptr);

		return NULL;
	}

	return NULL;
#endif
}

/**
 * 	@param FenceEvent **: indexed collection of 'FenceEvents *'. It may contain null elements.
 * 	@dynamic_memory: NONE. Imported  'fence_events **' is managed by caller
 */
//FenceRecord **
CollectionDescriptor *
MakeFenceRecordsListFromFenceEventsInProto (Session *sesn_ptr, FenceEvent **fence_events, size_t fence_events_sz, unsigned long call_flags, CollectionDescriptor *collection_ptr_in)
{

	if (fence_events_sz==0 || IS_EMPTY(fence_events))
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', size:'%lu'}: NOTICE: Received empty Events List.", __func__, pthread_self(), sesn_ptr, fence_events_sz);
#endif
		return NULL;
	}

	void 					*fence_record_ptr	= NULL;
	FenceRecord 			**fence_records		= NULL;

	fence_records	=calloc(fence_events_sz, sizeof(FenceRecord *));
	fence_record_ptr=calloc(fence_events_sz, sizeof(FenceRecord));

#if __VALGRIND_DRD
	VALGRIND_CREATE_MEMPOOL(fence_records, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(fence_records, fence_events_sz*(sizeof(FenceRecord *)));

	VALGRIND_CREATE_MEMPOOL(fence_record_ptr, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(fence_record_ptr, fence_events_sz*(sizeof(FenceRecord)));
#endif

	int 			i,
					processed_counter	= 0;
	FenceRecord 	*urec_ptr_aux;
	FenceRecord 	*urec_ptr_aux2[1];

	for (i=0; i<fence_events_sz; i++)
	{
		if (IS_EMPTY(fence_events[i]))
		{
#if __UF_TESTING
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', idx:'%d'} NOTICE: Fence Collection contained NULL reference...", __func__, pthread_self(), sesn_ptr, i);
#endif

			continue;
		}

#if __VALGRIND_DRD
		VALGRIND_MEMPOOL_ALLOC(fence_records, fence_records+processed_counter, sizeof(FenceRecord *));
		VALGRIND_MEMPOOL_ALLOC(fence_record_ptr, fence_record_ptr+(processed_counter*sizeof(FenceRecord)), sizeof(FenceRecord));
#endif
		urec_ptr_aux2[0] = (FenceRecord *)(fence_record_ptr+(processed_counter*sizeof(FenceRecord)));//chunk up vector as needed
		urec_ptr_aux = urec_ptr_aux2[0];

		fence_record__init(urec_ptr_aux);
		urec_ptr_aux->fid = fence_events[i]->target_id; urec_ptr_aux->has_fid=1;
		urec_ptr_aux->eid = fence_events[i]->eid; urec_ptr_aux->has_eid=1;

		fence_records[processed_counter] = fence_record_ptr;//connect the record to the array

#if __UF_TESTING
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', eid:'%lu', idx:'%d'} Adding FenceEvent reference...", __func__, pthread_self(), sesn_ptr, urec_ptr_aux->fid, urec_ptr_aux->eid, i);
#endif

		processed_counter++;
	}//for

	//return fence_records;

	CollectionDescriptor *collection_ptr = NULL;
	if (IS_EMPTY(collection_ptr_in))	collection_ptr=calloc(1, sizeof(CollectionDescriptor));
	else								collection_ptr = collection_ptr_in;

	collection_ptr->collection = (collection_t **)fence_records;
	collection_ptr->collection_sz = processed_counter;

	return collection_ptr;

}

/**
 * 	@brief: Build fence's own invite list ito proto
 * 	@returns: on error NULL, or 'FenceUserRecordsDescription *'. User must check for the number of elements,
 * 	as zero is not considered an error.
 *
 * 	@dynamic_memory: EXPORTS 'FenceUserRecordsDescription *' which the user is responsible for freeing
 * 	@call_flag FENCE_CALLFLAG_LOCK_FENCE:
 */
FenceUserRecordsDescription *
MakeFenceInviteListInProto (Session *sesn_ptr, Fence *f_ptr, unsigned call_flags)
{
	bool fence_lock_already_owned = false;
	//vector based allocation
	//this is not ready: record poulation function is not implement. Valgrid client code needs to be uncommented in the free functions above
	if (call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		 FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		 if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	return NULL;

		 fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	}

	UserRecord 					**user_records	= NULL;
	void /*UserRecord*/					*user_rec_ptr	= NULL;
	FenceUserRecordsDescription	*desc_ptr		= NULL;

	desc_ptr = calloc(1, sizeof(FenceUserRecordsDescription));

	if (FENCE_INVITED_LIST_EMPTY(f_ptr)) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: NOTICE: Received empty Invite Members List.", __func__, pthread_self(), sesn_ptr);
#endif

		goto exit_with_result; //albeit with zero-based result
	}

	user_records = calloc(FENCE_INVITED_LIST_SIZE(f_ptr), sizeof(UserRecord *));//we may fill less than that if flag not set: CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE
	user_rec_ptr = calloc(FENCE_INVITED_LIST_SIZE(f_ptr), sizeof(UserRecord));

#if __VALGRIND_DRD
	//note: these valgrind client calls are only needed to silence valgrind during instrumentation
	VALGRIND_CREATE_MEMPOOL(user_records, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_records, FENCE_USERS_COUNT(f_ptr)*(sizeof(UserRecord *)));

	VALGRIND_CREATE_MEMPOOL(user_rec_ptr, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_rec_ptr, FENCE_INVITED_LIST_SIZE(f_ptr)*(sizeof(UserRecord)));
#endif

	int i,
		processed_counter		= 0;
	Session 	*sesn_ptr_aux	= NULL;
	ListEntry 	*eptr			= NULL;
	UserRecord 	*urec_ptr_aux2[1];
	UserRecord 	*urec_ptr_aux;

	for (eptr=f_ptr->fence_user_sessions_invited_list.head; eptr; eptr=eptr->next) {
	   //UserRecord *urec_ptr_aux=(UserRecord *)(user_rec_ptr+(processed_counter*sizeof(UserRecord)));//chunk up vector as needed
#if __VALGRIND_DRD
		VALGRIND_MEMPOOL_ALLOC(user_records, user_records + processed_counter, sizeof(UserRecord *));
		VALGRIND_MEMPOOL_ALLOC(user_rec_ptr, user_rec_ptr + (processed_counter * sizeof(UserRecord)), sizeof(UserRecord));
#endif

		urec_ptr_aux2[0] = (UserRecord *)(user_rec_ptr+(processed_counter*sizeof(UserRecord)));//chunk up vector as needed
		urec_ptr_aux = urec_ptr_aux2[0];

		sesn_ptr_aux = SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever);

		if (IS_OK(MakeUserRecordFromSessionInProto(sesn_ptr_aux, urec_ptr_aux, PROTO_USER_RECORD_MINIMAL, false))) {
			user_records[processed_counter] = urec_ptr_aux;//connect the record to the array
			//urec_ptr_aux->location=MakeUserLocationInProto(&(ss_ptr->user), true/*digest_mode*/);
		}
		else continue;

		processed_counter++;
	}

	if (processed_counter > 0) {
		desc_ptr->records_sz = processed_counter;
		desc_ptr->user_records = user_records;

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: FINISHED PROTO representation for Invited members list. User count '%lu'", __func__, pthread_self(), sesn_ptr, desc_ptr->records_sz);
#endif

		//can be zero-base result
		exit_with_result:
		if (call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
			if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
		}

		return desc_ptr;
	} else {
		free(user_rec_ptr);
		free (user_records);
		free(desc_ptr);

#if __VALGRIND_DRD
		VALGRIND_DESTROY_MEMPOOL(user_rec_ptr);
		VALGRIND_DESTROY_MEMPOOL(user_records);
#endif

		return NULL;
	}

}

/**
 * 	@brief:
 * 	Retrieve list of user sessions from Fence and build it into protobuf representation. Utilises local cache; no backend query
 * 	@returns: never returns NULL
	@call_flag: FENCE_CALLFLAG_LOCK_FENCE
	@call_flag:	CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE

 * 	@locks RW f_ptr: when FENCE_CALLFLAG_LOCK_FENCE is flagged
 *
 * 	@dynamic_memory: ALLOCATES return in 'FenceUserRecordsDescription  *' which user must free
 * 	@dynamic_memory: ALLOCATES array of UserRecord saved in 'FenceUserRecordsDescription->user_records' which user must free
 */
FenceUserRecordsDescription  *
MakeFenceMembersInProto (InstanceContextForSession *ctx_ptr,  InstanceContextForFence *ctx_f_ptr, unsigned long sesn_call_flags, unsigned long fence_call_flags)
{
	bool fence_lock_already_owned = false;
  Session *sesn_ptr_this = ctx_ptr->sesn_ptr;
  Fence *f_ptr = ctx_f_ptr->f_ptr;

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr_this), __func__);

	 if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr_this, RESULT_TYPE_ERR))	return NULL;

	 fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	}

	ListEntry 									*eptr			= NULL;
	FenceUserRecordsDescription	*desc_ptr	= NULL;

	desc_ptr = calloc(1, sizeof(FenceUserRecordsDescription));

	if (FENCE_USERS_COUNT(f_ptr) == 0) {
		if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
			if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_this));
		}

		return desc_ptr;
	}

	//first check user in Fence's List

	//is user list loaded
  if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY)) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', fid:'%lu', users_sz:'%d'): FENCE has F_ATTR_SESSNLIST_LAZY flag: LOADING USER LIST FROM BACKEND", __func__, pthread_self(), FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr));
  }

  GetMembersListCacheRecordForFence(sesn_ptr_this, ctx_f_ptr->instance_f_ptr, UNSPECIFIED_UID, UNSPECIFIED_FENCE_LISTTYPE, UNSPECIFIED_FENCE_LISTTYPE, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);
  if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr_this, RESULT_TYPE_ERR)) {
    free (desc_ptr);
    return NULL;
  }

  //this should not happen given the above check, unless of data integrity issues: local fence has members, but backend is empty
  if (SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_BACKEND_DATA_EMPTYSET)) {
    syslog(LOG_ERR, LOGSTR_FENCE_BACKEND_USERLIST_MISMATCH, __func__, pthread_self(), sesn_ptr_this, f_ptr, FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr), LOGCODE_FENCE_BACKEND_USERLIST_MISMATCH);

    free(desc_ptr);
    return NULL;
  }

	int 				processed_counter;
	UserRecord 	**user_records;
	void 				*user_rec_ptr;
	UserRecord 	*urec_ptr_aux;

	user_records = calloc(FENCE_USERS_COUNT(f_ptr), sizeof(UserRecord *));//we may fill less than that if flag not set: CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE
	user_rec_ptr = calloc(FENCE_USERS_COUNT(f_ptr), sizeof(UserRecord));

#if __VALGRIND_DRD
	VALGRIND_CREATE_MEMPOOL(user_records, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_records, FENCE_USERS_COUNT(f_ptr)*(sizeof(UserRecord *)));

	VALGRIND_CREATE_MEMPOOL(user_rec_ptr, 0, 1);
	VALGRIND_MAKE_MEM_NOACCESS(user_rec_ptr, FENCE_USERS_COUNT(f_ptr)*(sizeof(UserRecord)));
#endif

	processed_counter = 0;
	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {
	   static const char	*l = "unknown";
	   int 								network_status __attribute__((unused));
	   Session						*sesn_ptr_aux;

	   sesn_ptr_aux = SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever);

	   if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_REMOTE)) {
		   //if not set
		   if (!(sesn_call_flags&CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE)) {
#ifdef __UF_TESTING
			   syslog(LOG_DEBUG, "%s (pid:'%lu', o_remote:'%p', cid_remote:'%lu'): FOUND REMOTE SESSION: IGNORING...", __func__, pthread_self(), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux));
#endif
			   continue;
		   } else {
			   if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_REMOTE_CONNECTED)) {
				   network_status = 1;
			   }
			   //REMOTE & SUSPENDED
			   else
			   if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_SUSPENDED)) {
				   network_status = 2;
			   } else network_status = -1;

			   //control flows below to fill attributes
		   }
	   } else {
		   if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_CONNECTED)) {
			   network_status = 1;
		   } else if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_SUSPENDED)) {
			   network_status = 2;
		   } else network_status = -1;
	   }

#if __VALGRIND_DRD
		VALGRIND_MEMPOOL_ALLOC(user_records, user_records + processed_counter, sizeof(UserRecord *));
		VALGRIND_MEMPOOL_ALLOC(user_rec_ptr, (user_rec_ptr + (processed_counter * sizeof(UserRecord))), sizeof(UserRecord));
#endif

		UserRecord *urec_ptr_aux2[1];
		urec_ptr_aux2[0] = (UserRecord *)(user_rec_ptr + (processed_counter * sizeof(UserRecord)));//chunk up vector as needed
		urec_ptr_aux = urec_ptr_aux2[0];

		if (IS_OK(MakeUserRecordFromSessionInProto(sesn_ptr_aux, urec_ptr_aux, PROTO_USER_RECORD_MINIMAL, false))) {
			//urec_ptr_aux->location=MakeUserLocationInProto(&(ss_ptr->user), true/*digest_mode*/);
			InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = IsUserMemberOfThisFence((SESSION_FENCE_LIST_PTR(sesn_ptr_aux)), f_ptr, false);
				if (IS_PRESENT(instance_fstate_ptr)) {
				  FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
					if (IS_SET_FENCE_USERPREF(fstate_ptr, profile_sharing))	{
						urec_ptr_aux->profile_key.data	=	(uint8_t *)SESSION_USER_PROFILE_KEY(sesn_ptr_aux);
						urec_ptr_aux->profile_key.len		=	CONFIG_USER_PROFILEKEY_MAX_SIZE;
						urec_ptr_aux->has_profile_key		=	1;

						if (IS_STR_LOADED(SESSION_USERAVATAR(sesn_ptr_aux))) {
							AttachmentDescriptor attachment_descriptor_out = {{0}};

							if (!IS_PRESENT(GetAttachmentDescriptorEphemeral(sesn_ptr_this, SESSION_USERAVATAR(sesn_ptr_aux), true/*full record*/, &attachment_descriptor_out))) {
								syslog(LOG_ERR, "%s (pid:'%lu', o_aux:'%p', cid_aux:'%lu', avarad_id:'%s'): ERROR: SESSION STORED AVATAR DOESNT HAVE CORRESPONDING STORAGE", __func__, pthread_self(), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), SESSION_USERAVATAR(sesn_ptr_aux));
								continue;
							}
              //todo: perhaps reuse already allocated members of attachment_descriptor_out instead of the dup flag
							AttachmentRecord *attachment_record_ptr = MakeAttachmentRecordInProto(&attachment_descriptor_out, NULL, true/*flag_dup*/);

							AttachmentDescriptorDestruct(&attachment_descriptor_out, true, false);

							urec_ptr_aux->avatar		=	attachment_record_ptr;
						}
					}

					user_records[processed_counter] = urec_ptr_aux;
				} else {
				//this is a major stuff up
				syslog(LOG_DEBUG, "%s (pid:'%lu', o_aux:'%p', cid_aux:'%lu', fo:'%p'): ERROR: FOUND USER IN FENCE'S LIST BUT USER DOESN'T HAVE CORRESPONDING FENCESTATE", __func__, pthread_self(), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), f_ptr);
				continue;
			}
		}
		else continue;

		processed_counter++;
	}//for

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_this));
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', dname:'%s', users_sz:'%d'): FINISHED PROTO representation.", __func__, pthread_self(), FENCE_DNAME(f_ptr), FENCE_USERS_COUNT(f_ptr));
#endif

	desc_ptr->records_sz = processed_counter;
	desc_ptr->user_records = user_records;

	return desc_ptr;

}

/**
 *
 */
__unused CollectionDescriptor *
MakeAttachmentRecordsInProto (CollectionDescriptor *collection_attachment_descriptors, CollectionDescriptor *collection_attachment_records_out, bool flag_dup)
{
	AttachmentRecord 			*attachment_record_ptr;
	AttachmentDescriptor 	*attachment_descriptor_ptr __unused;

	for (size_t i=0; i<collection_attachment_descriptors->collection_sz; i++)
	{
		attachment_record_ptr			=	(AttachmentRecord *)collection_attachment_records_out->collection[i];
		attachment_descriptor_ptr	=	(AttachmentDescriptor *)collection_attachment_descriptors->collection[i];

		MakeAttachmentRecordInProto (attachment_descriptor_ptr, attachment_record_ptr, flag_dup);
	}

	return collection_attachment_records_out;
}

/**
 * 	@brief: This only does referential assignment. Don't hold on to data for too long.
 * 	This is temporary treatment as curenly attachment data for fence avatars are not saved directly in FenceRecord, but needs
 * 	to be retrieved from GroupContext.
 * 	Similar to TEMPMakeAttachmentRecordFromAttachmentPointerInProto but not intended for packing, so it doesn't
 * 	initialise protobuf message.
 *
 * 	@dynamic_memory: allocate 'AttachmentRecord *' if none was passed
 */
AttachmentRecord *
TransferFenceAvatarAttachmentIfPresent (AttachmentPointer *attachment_pointer_ptr, AttachmentRecord *record_ptr_out)
{
	if (IS_PRESENT(attachment_pointer_ptr))
	{
		AttachmentRecord *record_ptr = NULL;
		if (IS_EMPTY(record_ptr_out)) 	record_ptr=calloc(1, sizeof(AttachmentPointer));
		else														record_ptr=record_ptr_out;

		record_ptr->filename			=	attachment_pointer_ptr->filename;
		record_ptr->contenttype		=	attachment_pointer_ptr->contenttype;
		record_ptr->id						=	attachment_pointer_ptr->ufid;
		record_ptr->key						=	attachment_pointer_ptr->key;
		record_ptr->has_key				=	attachment_pointer_ptr->has_key;
		record_ptr->size					=	attachment_pointer_ptr->size;
		record_ptr->has_size			=	attachment_pointer_ptr->has_size;
		record_ptr->width					=	attachment_pointer_ptr->width;
		record_ptr->has_width			=	attachment_pointer_ptr->has_width;
		record_ptr->height				=	attachment_pointer_ptr->height;
		record_ptr->has_height	  =	attachment_pointer_ptr->has_height;
		record_ptr->thumbnail			=	attachment_pointer_ptr->thumbnail;
		record_ptr->has_thumbnail	=	attachment_pointer_ptr->has_thumbnail;
		record_ptr->digest				=	attachment_pointer_ptr->digest;
		record_ptr->has_digest		=	attachment_pointer_ptr->has_digest;
		record_ptr->flags					=	attachment_pointer_ptr->flags;

		return record_ptr;

	}

	return NULL;
}

/**
 * 	@brief: TEMPORARY given a AttachmentPointer transfer data to a new AttachmentRecord holder.
 * 	@WARNING: ALL ELEMENTS ARE ASSIGNED BY REFERENCE --> KEEP AttachmentPointer in scope until done with.
 * 	@dynamic_memory: No need to deallocate attachment_record_ptr as the original data will be destoryed when
 * 	attachment_pointer_ptr is free_unpacked() (provding it originated from unpacked source)
 * 	@param collection_attachment_records_out: preallocated with one holder by user
 */
CollectionDescriptor *
TEMPMakeAttachmentRecordFromAttachmentPointerInProto (AttachmentPointer *attachment_pointer_ptr, CollectionDescriptor *collection_attachment_records_out)
{
	AttachmentRecord 			*attachment_record_ptr;

	attachment_record_ptr			=	(AttachmentRecord *)collection_attachment_records_out->collection[0];
	(void)attachment_record__init(attachment_record_ptr);

	attachment_record_ptr->key					=	attachment_pointer_ptr->key; 					attachment_record_ptr->has_key				=	attachment_pointer_ptr->has_key;
	attachment_record_ptr->digest				=	attachment_pointer_ptr->digest; 			attachment_record_ptr->has_digest			=	attachment_pointer_ptr->has_digest;
	attachment_record_ptr->size					=	attachment_pointer_ptr->size;				 	attachment_record_ptr->has_size				=	attachment_pointer_ptr->has_size;
	attachment_record_ptr->width				=	attachment_pointer_ptr->width; 				attachment_record_ptr->has_width				=	attachment_pointer_ptr->has_width;
	attachment_record_ptr->height				=	attachment_pointer_ptr->height; 				attachment_record_ptr->has_height				=	attachment_pointer_ptr->has_height;
	attachment_record_ptr->thumbnail		=	attachment_pointer_ptr->thumbnail;		attachment_record_ptr->has_thumbnail	=	attachment_pointer_ptr->has_thumbnail;
	attachment_record_ptr->contenttype	=	attachment_pointer_ptr->contenttype;
	attachment_record_ptr->id						=	attachment_pointer_ptr->ufid;

	return collection_attachment_records_out;
}

/**
 * 	THIS TEMPORARY READS OF ATTACHMENT FROM ATTACHMENTPOINTER AS OPPOSED TO ATTACHMENTRECORD.
 * 	See AttachmentDescriptorGetFromProto ()
 */
AttachmentDescriptor *
TEMPAttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentPointer *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key)
{
	if (unlikely(IS_EMPTY(attachment_record)))	return NULL;

	if (unlikely(attachment_record->size <= 0))	return NULL;

	if (unlikely(IS_EMPTY(attachment_record->ufid)))	return NULL;

	AttachmentDescriptor *attachment_ptr = NULL;

	if (!IS_EMPTY(attachment_descriptor_ptr_in))	attachment_ptr = attachment_descriptor_ptr_in;
	else 																					attachment_ptr = calloc(1, sizeof(AttachmentDescriptor));

	strncpy(attachment_ptr->id, attachment_record->ufid, MBUF-1);
	if (attachment_record->has_key) {
		memcpy(attachment_ptr->key, attachment_record->key.data, attachment_record->key.len>MBUF?MBUF:attachment_record->key.len);
		attachment_ptr->key_sz = attachment_record->key.len>MBUF?MBUF:attachment_record->key.len;

		if (flag_encode_key) {
			attachment_ptr->key_encoded = (char *)base64_encode((unsigned char *)attachment_ptr->key, attachment_ptr->key_sz, NULL);
		}
	}

	if (attachment_record->has_digest) {
		memcpy(attachment_ptr->digest, attachment_record->digest.data, attachment_record->digest.len>MBUF?MBUF:attachment_record->digest.len);
		attachment_ptr->digest_sz = attachment_record->digest.len>MBUF?MBUF:attachment_record->digest.len;

		if (flag_encode_key) {
			attachment_ptr->digest_encoded = (char *)base64_encode((unsigned char *)attachment_ptr->digest, attachment_ptr->digest_sz, NULL);
		}
	}

	size_t sz;
  if (IS_STR_LOADED(attachment_record->blurhash) && ((sz = strlen(attachment_record->blurhash)) <= CONFIGDEFAULT_MAX_IMAGE_BLURHASH_SZ)) {
    attachment_ptr->blurhash = strndup(attachment_record->blurhash,  sz);
  }

  if (IS_STR_LOADED(attachment_record->caption) && ((sz = strlen(attachment_record->caption)) <= CONFIGDEFAULT_MAX_IMAGE_CAPTION_SZ)) {
    attachment_ptr->caption = strndup(attachment_record->caption,  sz);
  }

	if (!IS_EMPTY(attachment_record->contenttype)) {
		size_t contenttype_sz = strlen(attachment_record->contenttype);
		strncpy(attachment_ptr->mime_type, attachment_record->contenttype, contenttype_sz>SBUF-1?SBUF-1:contenttype_sz);
	}

	attachment_ptr->width   = attachment_record->width;
	attachment_ptr->height  = attachment_record->height;
	attachment_ptr->size    = attachment_record->size;
	attachment_ptr->eid     = eid;

#if 1//__UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', id:'%s', key:'%s', mime:'%s', size:'%lu'}: Attachment... ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
		attachment_ptr->id, attachment_ptr->key_encoded?attachment_ptr->key_encoded:"", attachment_ptr->mime_type, attachment_ptr->size);
#endif

	return attachment_ptr;

}

/**
 * 	@dynamic_memory: EXPORTS various fields
 */
AttachmentDescriptor *
AttachmentDescriptorGetFromProto (Session *sesn_ptr, AttachmentRecord *attachment_record, size_t eid, AttachmentDescriptor *attachment_descriptor_ptr_in, bool flag_encode_key)
{
	if (unlikely(IS_EMPTY(attachment_record)))	return NULL;

	if (unlikely(attachment_record->size <= 0))	return NULL;

	if (unlikely(IS_EMPTY(attachment_record->id)))	return NULL;

	AttachmentDescriptor *attachment_ptr = NULL;

	if (!IS_EMPTY(attachment_descriptor_ptr_in))	attachment_ptr = attachment_descriptor_ptr_in;
	else 																					attachment_ptr = calloc(1, sizeof(AttachmentDescriptor));

	strncpy(attachment_ptr->id, attachment_record->id, MBUF-1);
	if (attachment_record->has_key) {
		memcpy(attachment_ptr->key, attachment_record->key.data, attachment_record->key.len>MBUF?MBUF:attachment_record->key.len);
		attachment_ptr->key_sz = attachment_record->key.len>MBUF?MBUF:attachment_record->key.len;

		if (flag_encode_key) {
			attachment_ptr->key_encoded = (char *)base64_encode((unsigned char *)attachment_ptr->key, attachment_ptr->key_sz, NULL);
		}
	}

	if (attachment_record->has_digest) {
		memcpy(attachment_ptr->digest, attachment_record->digest.data, attachment_record->digest.len>MBUF?MBUF:attachment_record->digest.len);
		attachment_ptr->digest_sz = attachment_record->digest.len>MBUF?MBUF:attachment_record->digest.len;

		if (flag_encode_key) {
			attachment_ptr->digest_encoded = (char *)base64_encode((unsigned char *)attachment_ptr->digest, attachment_ptr->digest_sz, NULL);
		}
	}

  size_t sz;
  if (IS_STR_LOADED(attachment_record->blurhash) && ((sz = strlen(attachment_record->blurhash)) <= CONFIGDEFAULT_MAX_IMAGE_BLURHASH_SZ)) {
    attachment_ptr->blurhash = strndup(attachment_record->blurhash,  sz);
  }

  if (IS_STR_LOADED(attachment_record->caption) && ((sz = strlen(attachment_record->caption)) <= CONFIGDEFAULT_MAX_IMAGE_CAPTION_SZ)) {
    attachment_ptr->caption = strndup(attachment_record->caption,  sz);
  }

	if (!IS_EMPTY(attachment_record->contenttype)) {
		size_t contenttype_sz=strlen(attachment_record->contenttype);
		strncpy(attachment_ptr->mime_type, attachment_record->contenttype, contenttype_sz>SBUF-1?SBUF-1:contenttype_sz);
	}

	attachment_ptr->width = attachment_record->width;
	attachment_ptr->height = attachment_record->height;
	attachment_ptr->size = attachment_record->size;
	attachment_ptr->eid = eid;

#if __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', id:'%s', key:'%s', mime:'%s', size:'%lu', key_size:'%lu, eid:'%lu'}: Generated AttachmentDescriptor... ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
		attachment_ptr->id, attachment_ptr->key_encoded?attachment_ptr->key_encoded:"", attachment_ptr->mime_type, attachment_ptr->size, attachment_ptr->key_sz, eid);
#endif

	return attachment_ptr;

}

LocationRecord *
MakeUserLocationInProto (const User *user_ptr, bool flag_digest_mode)
{
	if (unlikely(IS_EMPTY(user_ptr)))	return NULL;

	const LocationDescription *location_desc_ptr		= NULL;
	LocationRecord 						*location_record_ptr	= NULL;

	if (user_ptr->user_details.user_location_initialised)	location_desc_ptr=&(user_ptr->user_details.user_location);
	else
	if (user_ptr->user_details.user_location_by_server_initialised)	location_desc_ptr=&(user_ptr->user_details.user_location_by_server);
	else
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', uname:'%s'} ERROR: Could not find a valid LocationDescription for user...", __func__, pthread_self(), user_ptr->user_details.user_name);

		return NULL;
	}

	location_record_ptr=MakeLocationDescriptionInProto (location_desc_ptr, flag_digest_mode, true, NULL);

	if (IS_FALSE(flag_digest_mode))	if (user_ptr->user_details.baseloc_prefix) location_record_ptr->baseloc=strdup(user_ptr->user_details.baseloc_prefix);

	return location_record_ptr;

}

LocationRecord *
MakeFenceLocationInProto (const Fence *f_ptr, bool flag_digest_mode)
{
	if (unlikely(IS_EMPTY(f_ptr)))	return NULL;

	LocationRecord *location_record_ptr=NULL;
	location_record_ptr=MakeLocationDescriptionInProto (&(f_ptr->fence_location.fence_location), flag_digest_mode, true, NULL);

	if (IS_FALSE(flag_digest_mode))	if (f_ptr->fence_location.base_location) location_record_ptr->baseloc=strdup(f_ptr->fence_location.base_location);

	return location_record_ptr;

#if 0
	LocationRecord *location_record_ptr;
	location_record_ptr=calloc(1, sizeof(LocationRecord));
	location_record__init(location_record_ptr);

	if (IS_TRUE(flag_digest_mode))
	{
		if (f_ptr->fence_location.fence_location.admin_area) location_record_ptr->adminarea=strdup(f_ptr->fence_location.fence_location.admin_area);
		if (f_ptr->fence_location.fence_location.country) location_record_ptr->country=strdup(f_ptr->fence_location.fence_location.country);
		if (f_ptr->fence_location.fence_location.locality) location_record_ptr->locality=strdup(f_ptr->fence_location.fence_location.locality);
		if (f_ptr->fence_location.base_location) location_record_ptr->baseloc=strdup(f_ptr->fence_location.base_location);
		location_record_ptr->longitude=f_ptr->fence_location.fence_location.longitude;
		location_record_ptr->latitude=f_ptr->fence_location.fence_location.latitude;
	}
	else
	{
		location_record_ptr->longitude=f_ptr->fence_location.fence_location.longitude;
		location_record_ptr->latitude=f_ptr->fence_location.fence_location.latitude;
		if (f_ptr->fence_location.fence_location.locality) location_record_ptr->locality=strdup(f_ptr->fence_location.fence_location.locality);
	}

	return location_record_ptr;
#endif
}

/**
 * 	@param flag_digest_mode: if set to true, fewer fields are included
 * 	@returns: fully initialised  LocationRecord proto ready for packing
 *
 * 	@locked: user's responsibility to lock source User or fence if that was necessary
 * 	@locks: NONE
 * 	@dynamic_memory: EXPORTS dynamic fields which user must free either individually, or through DestructLocationRecordInProto()
 * 	@destructor_function: DestructLocationRecordInProto()
 */
LocationRecord *
MakeLocationDescriptionInProto (const LocationDescription *loc_ptr, bool flag_digest_mode, bool flag_dup_mode, LocationRecord *location_record_ptr_out)
{
	if (unlikely(IS_EMPTY(loc_ptr)))	return NULL;

	LocationRecord *location_record_ptr;

	if (IS_PRESENT(location_record_ptr_out))	location_record_ptr = location_record_ptr_out;
	else																			location_record_ptr = calloc(1, sizeof(LocationRecord));

	location_record__init(location_record_ptr);

	if (IS_FALSE(flag_digest_mode))
	{
		if (loc_ptr->admin_area) 	IS_TRUE(flag_dup_mode)?(location_record_ptr->adminarea	=	strdup(loc_ptr->admin_area)):(location_record_ptr->adminarea=loc_ptr->admin_area);
		if (loc_ptr->country) 		IS_TRUE(flag_dup_mode)?(location_record_ptr->country		=	strdup(loc_ptr->country)):(location_record_ptr->country=loc_ptr->country);
		if (loc_ptr->locality) 		IS_TRUE(flag_dup_mode)?(location_record_ptr->locality		=	strdup(loc_ptr->locality)):(location_record_ptr->locality=loc_ptr->locality);

		location_record_ptr->longitude = loc_ptr->longitude;
		location_record_ptr->latitude = loc_ptr->latitude;
	}
	else
	{
		location_record_ptr->longitude = loc_ptr->longitude;
		location_record_ptr->latitude = loc_ptr->latitude;
		if (loc_ptr->locality) 		IS_TRUE(flag_dup_mode)?(location_record_ptr->locality = strdup(loc_ptr->locality)):(location_record_ptr->locality=loc_ptr->locality);
	}

	return location_record_ptr;

}

void
DestructLocationRecordInProto (LocationRecord *location_record_ptr, bool flag_self_destruct)
{
	if (unlikely(IS_EMPTY(location_record_ptr)))	return;

	if (!IS_EMPTY(location_record_ptr->adminarea))	{free (location_record_ptr->adminarea);	location_record_ptr->adminarea=NULL;}
	if (!IS_EMPTY(location_record_ptr->country))	{free (location_record_ptr->country);	location_record_ptr->country=NULL;}
	if (!IS_EMPTY(location_record_ptr->locality))	{free(location_record_ptr->locality);	location_record_ptr->locality=NULL;}
	if (!IS_EMPTY(location_record_ptr->baseloc))	{free(location_record_ptr->baseloc);	location_record_ptr->baseloc=NULL;}

	if (flag_self_destruct)	{free (location_record_ptr);	location_record_ptr=NULL;}

}

/**
 * 	@brief: iterates ofver a collection of UserRecords and performs deep deallocation
 */
void
DestructUserRecords (UserRecord **user_records, size_t user_records_sz)
{
	if (unlikely(user_records == NULL)) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "UserRecor **");
		return;
	}

	if (user_records_sz > 0) {
		syslog(LOG_DEBUG, "%s: FREEING %lu members...", __func__, user_records_sz);

		int idx_members=user_records_sz-1;
		for (; idx_members>=0; idx_members--) {
			UserRecord *user_record_ptr = user_records[idx_members];
			DestructUserInfoInProto (user_record_ptr, false/*flag_self_destruct*/);
			DestructLocationRecordInProto (user_record_ptr->location, true);

			if (user_record_ptr->n_fences) {
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s: FREEING count:'%lu' fences...", __func__, user_record_ptr->n_fences);
#endif
				int user_fences_idx = user_record_ptr->n_fences - 1;

				for (; idx_members>=0; idx_members--) {
					FenceRecord *user_fence_record = user_record_ptr->fences[idx_members];
					if (user_fence_record->cname)	free(user_fence_record->cname);
					if (user_fence_record->fname)	free(user_fence_record->fname);

					DestructLocationRecordInProto(user_fence_record->location, true);
				}

				free(user_record_ptr->fences);
			}
		}//for

		DestructUserRecordsProto(user_records, user_records_sz, true);
	}
}

/**
 * 	@IMPORTANT: if FenceRecord was part of a previously allocated array, DONT FREE IT. ONLY SELF DESTRUCT IF
 * 	THE RECORD WAS INDIVIDUALLY HEAP_ALLOCATED
 * 	@IMPORTANT: Where userid (owner_uid., and invited_by) have data present, they'll be automatically deallocated. If that's not
 * 	desirable, user must NULLify
 */
void
DestructFenceRecordProto (FenceRecord *fence_record_ptr, bool flag_self_destruct)
{
	if (fence_record_ptr->cname) free(fence_record_ptr->cname);
	if (fence_record_ptr->fname) free(fence_record_ptr->fname);

	DestructLocationRecordInProto(fence_record_ptr->location, true);

	if (IS_PRESENT(fence_record_ptr->avatar)) DestructAttachmentRecord(fence_record_ptr->avatar, true);

	if (fence_record_ptr->n_members > 0) DestructUserRecords(fence_record_ptr->members, fence_record_ptr->n_members);
	if (fence_record_ptr->n_invited_members > 0) DestructUserRecords(fence_record_ptr->invited_members, fence_record_ptr->n_invited_members);
	if (fence_record_ptr->n_fence_preferences > 0) DestructFenceUserPreferencesInProto(fence_record_ptr);
	DestructFencePermissionsInProto(fence_record_ptr);

	if (IS_PRESENT(fence_record_ptr->owner_uid.data))	{
		free(fence_record_ptr->owner_uid.data);
	}

	if (IS_PRESENT(fence_record_ptr->invited_by.data))	{
		free(fence_record_ptr->invited_by.data);
	}

	if (flag_self_destruct)	free(fence_record_ptr);
}

/**
 * 	@WARNING: ONLY USE SELF_DESTRUCT IF THE THE OBJECT WAS HEAP ALLOCATED. THIS TEST APPLIES TO INDIVIDUAL CONTAINED
 * 	FENCE RECORDS< WHO ARE ALLOCATED VIA A INGLE VECTOR I.E. NOT INDIVIDUALLY.
 *
 * 	@brief: very deep destructor of a given FenceRecords array.
 * 	There are two allocations embedded:
 * 	1)fence_records_ptr --> contiguous vector for as many fences
 * 	2)fence_records_ptr[0] --> contiguous vector of FenceRecord for as many fences
 *
 */
void
DestructFenceRecordsProto (FenceRecord **fence_records_ptr, unsigned count, bool flag_self_destruct, bool self_destruct_record)
{
	if (fence_records_ptr && count) {
		int idx = count - 1;
		for (; idx>=0; idx--) {
			FenceRecord *fence_record_ptr;
			fence_record_ptr = fence_records_ptr[idx];

			//TODO: REPLACE THIS BLOCK WITH FUNCTION ABOVE. MAKE SURE SELF_DESTRUCT IS USED CORRECTLY BY CLIENTS
			if (fence_record_ptr->cname) free(fence_record_ptr->cname);
			if (fence_record_ptr->fname) free(fence_record_ptr->fname);

			DestructLocationRecordInProto (fence_record_ptr->location, true);

			if (fence_record_ptr->avatar) {
				if (fence_record_ptr->avatar->contenttype) free(fence_record_ptr->avatar->contenttype);
				if (fence_record_ptr->avatar->has_thumbnail)	free(fence_record_ptr->avatar->thumbnail.data);
				if (fence_record_ptr->avatar->has_key)	free(fence_record_ptr->avatar->key.data);
				if (fence_record_ptr->avatar->id)	free (fence_record_ptr->avatar->id);
				free(fence_record_ptr->avatar);
			}

			if (fence_record_ptr->n_members > 0) DestructUserRecords (fence_record_ptr->members, fence_record_ptr->n_members);
			if (fence_record_ptr->n_invited_members > 0) DestructUserRecords (fence_record_ptr->invited_members, fence_record_ptr->n_invited_members);

		}//for

		if (self_destruct_record) free (fence_records_ptr[0]);

		if (flag_self_destruct) {
			//free (fence_records_ptr[0]);//assuming vector... TODO: THIS SHOULD BE DONE HERE MAKE SURE CLIENTS ARE USING IN ACCORDANCE WITH WARNING ABOVE
			free (fence_records_ptr);
		}
	}

}

bool
isFenceDeliveryModelEquals (const Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode)
{
	bool is_delivery_mode_equal = false;

	switch (delivery_mode) {
		case FENCE_RECORD__DELIVERY_MODE__MANY:
			if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_MANY_TO_MANY))	{
				is_delivery_mode_equal = true;
			}
			break;

		case FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY:
			if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST_ONEWAY))	{
				is_delivery_mode_equal = true;
			}
			break;

		case FENCE_RECORD__DELIVERY_MODE__BROADCAST:
			if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST))	{
				is_delivery_mode_equal = true;
			}
			break;
	  case _FENCE_RECORD__DELIVERY_MODE_IS_INT_SIZE: break;
	}

	return is_delivery_mode_equal;
}

//todo: also see FSRVResult *UpdateFenceDeliveryModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode, unsigned long fence_call_flags)
void
SetFenceDeliveryModeFromProto (uint64_t *setting, FenceRecord__DeliveryMode delivery_mode)
{
	switch (delivery_mode) {
		case FENCE_RECORD__DELIVERY_MODE__BROADCAST:
			F_ATTR_SET(*setting, F_ATTR_BROADCAST);

			F_ATTR_UNSET(*setting, F_ATTR_BROADCAST_ONEWAY);
			F_ATTR_UNSET(*setting, F_ATTR_MANY_TO_MANY);
			break;

		case FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY:
			F_ATTR_SET(*setting, F_ATTR_BROADCAST_ONEWAY);

			F_ATTR_UNSET(*setting, F_ATTR_BROADCAST);
			F_ATTR_UNSET(*setting, F_ATTR_MANY_TO_MANY);
			break;

		case FENCE_RECORD__DELIVERY_MODE__MANY:
			F_ATTR_SET(*setting, F_ATTR_MANY_TO_MANY);

			F_ATTR_UNSET(*setting, F_ATTR_BROADCAST);
			F_ATTR_UNSET(*setting, F_ATTR_BROADCAST_ONEWAY);
			break;

	  case _FENCE_RECORD__DELIVERY_MODE_IS_INT_SIZE: break;

	}

}

/**
 * 	@brief: Validate attachments provided as a collection of AttachmentRecord in native protobuf format.
 * 	@WARNING: this does not use the TypePool for sourcing AttachmentDescriptor objects.
 * 	@param sesn_ptr user session responsible for the attachment
 * 	@param collection_attachments: collection of 'AttachmentRecord *'
 * 	@param collection_attachments_out: pre-allocated collection of 'AttachmentDescriptor *', but storage must be mapped back
 * 	to a continuous allocation pool of 'AttachmentDescriptor'.
 */
UFSRVResult *
AttachmentDescriptorValidateFromProto (Session *sesn_ptr, Fence *f_ptr, CollectionDescriptor *collection_attachments, size_t eid, bool flag_encode_key, CollectionDescriptor *collection_attachments_out)
{
  if ((collection_attachments->collection_sz > 0) && IS_PRESENT(collection_attachments->collection[0])) {
    size_t								success_idx							=	0;
    AttachmentRecord 			*attachment_record_ptr	=	NULL;
    AttachmentDescriptor 	*attachment_descriptor_ptr;

    for (size_t i=0; i<collection_attachments->collection_sz; i++) {
      attachment_descriptor_ptr = (AttachmentDescriptor *)collection_attachments_out->collection[i];//temp storage, we'll reuse it for real purpose below
      attachment_record_ptr     = (AttachmentRecord *)collection_attachments->collection[i];

      if (IS_PRESENT((GetAttachmentDescriptorEphemeral(sesn_ptr, attachment_record_ptr->id, false, attachment_descriptor_ptr)))) {
        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', blob_id:'%s'}: ERROR: ATTACHMENT ID ALREADY EXISTS", __func__, pthread_self(), sesn_ptr, attachment_record_ptr->id);

        collection_attachments_out->collection[i] = NULL; //slot is unavailable

        continue;
      }

      attachment_descriptor_ptr = (AttachmentDescriptor *)collection_attachments_out->collection[i];
      if (AttachmentDescriptorGetFromProto(sesn_ptr, attachment_record_ptr, eid, attachment_descriptor_ptr, flag_encode_key)) {
        DbAttachmentStore (sesn_ptr, attachment_descriptor_ptr, IS_PRESENT(f_ptr)?FENCE_ID(f_ptr):SESSION_USERID(sesn_ptr), 1);
        AttachmentDescriptorDestruct(attachment_descriptor_ptr, true, false);
        success_idx++;
      } else {
        collection_attachments_out->collection[i] = NULL; //null it to indicated failure
        syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', blocb_id:'%s'}: ERROR: COULD PARSE ATTACHMENT FROM PROTO", __func__, pthread_self(), sesn_ptr, attachment_record_ptr->id);
      }

    }

    collection_attachments_out->collection_sz = success_idx;
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_CONNECTION)
  }

  collection_attachments_out->collection_sz = 0;
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
}