/**
 * Copyright (C) 2015-2025 unfacd works
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

#ifndef UFSRV_DATA_USERPREFERENCEDESCRIPTOR_H
#define UFSRV_DATA_USERPREFERENCEDESCRIPTOR_H

#include <ufsrvmsg_core/user/user_preference_descriptor_type.h>

//convenient grouping of prefops for lookup use mainly by static const UserPreferenceDescriptor prefs_table[]
static const UserPreferenceOps prefs_ops_table[] = {
        {(UserPreferenceOpSet)SetUserPreferenceBoolean, (UserPreferenceOpGet)GetUserPreferenceBoolean, (UserPreferenceOpSetLocal)_SetLocalUserPreferenceBoolean, (UserPreferenceOpGetLocal)NULL},
        {(UserPreferenceOpSet)SetUserPreferenceInteger, (UserPreferenceOpGet)GetUserPreferenceInteger, (UserPreferenceOpSetLocal)NULL,                           (UserPreferenceOpGetLocal)NULL},
        {(UserPreferenceOpSet)SetUserPreferenceString,  (UserPreferenceOpGet)GetUserPreferenceString,  (UserPreferenceOpSetLocal)NULL,                           (UserPreferenceOpGetLocal)NULL},
        {NULL, NULL, NULL, NULL											},//PREFVALUETYPE_INT_MULTI
        {NULL, NULL, NULL, NULL											},//PREFVALUETYPE_STR_MULTI
        {NULL, NULL, NULL, NULL											},//PREFVALUETYPE_INVALID
};


#pragma region individul pref ops

//NICKNAME
UserPreferenceOps prefops_nickname = {
        (UserPreferenceOpSet)SetUserPreferenceNickname, (UserPreferenceOpGet)GetUserPreferenceNickname,(UserPreferenceOpSetLocal)_SetLocalUserPreferenceNickname, (UserPreferenceOpGetLocal)NULL
};
//

//AVATAR
//update methods
UserPreferenceOps prefops_avatar = {
        (UserPreferenceOpSet)SetUserPreferenceString, (UserPreferenceOpGet)GetUserPreferenceAvatar,(UserPreferenceOpSetLocal)_SetLocalUserPreferenceAvatar, (UserPreferenceOpGetLocal)NULL
};
//

UserPreferenceOps prefops_e164number = {
        (UserPreferenceOpSet)SetUserPreferenceString, (UserPreferenceOpGet)GetUserPreferenceE164Number,(UserPreferenceOpSetLocal)_SetLocalUserPreferenceE164Number, (UserPreferenceOpGetLocal)NULL
};

UserPreferenceOps prefops_sharelist_profile = {
        (UserPreferenceOpSet)SetUserPreferenceShareList, (UserPreferenceOpGet)GetUserPreferenceShareList,(UserPreferenceOpSetLocal)NULL, (UserPreferenceOpGetLocal)NULL
};
//

UserPreferenceOps prefops_guardian_uid = {
        (UserPreferenceOpSet)SetUserPreferenceInteger, (UserPreferenceOpGet)GetUserPreferenceInteger, (UserPreferenceOpSetLocal)_SetLocalGuardianUid, (UserPreferenceOpGetLocal)_GetLocalGuardianUid
};

UserPreferenceOps prefops_geoloc_trigger = {
        (UserPreferenceOpSet)SetUserPreferenceInteger, (UserPreferenceOpGet)GetUserPreferenceInteger, (UserPreferenceOpSetLocal)_SetLocalGeolocTrigger, (UserPreferenceOpGetLocal)_GetLocalGeolocTrigger
};

UserPreferenceOps prefops_baseloc_zone = {
        (UserPreferenceOpSet)SetUserPreferenceInteger, (UserPreferenceOpGet)GetUserPreferenceInteger, (UserPreferenceOpSetLocal) _SetLocalBaselocZone, (UserPreferenceOpGetLocal)_GetLocalBaselocZone
};

UserPreferenceOps prefops_homebase_loc = {
        (UserPreferenceOpSet)SetUserPreferenceString, (UserPreferenceOpGet)GetUserPreferenceString, (UserPreferenceOpSetLocal) _SetLocalHomebaseLoc, (UserPreferenceOpGetLocal)_GetLocalHomebaseLoc
};
#pragma endregion


//This needs to be kept in sync with enum UserPrefsOffsets{} and bitfields defined in struct UserPrefsBoolean{} in user_type.h
//slots 0-63 reserved for bools, organised in 8 groups of bytes. redis fetches by byte ranges, hence this supporting scheme
//For each added pref the plumbing looks like this:
//INTRA:
//HandleIntraBroadcastForUser () -> _CommandControllerPreferences () -> _CommandControllerUserPrefNickname () -> IsUserAllowedToChangeNickname() ->
//	... SetUserPreferenceString() -> InterBroadcastUserNicknameMessage() -> _MarshalUserNicknameUpdate ()-> _MarshalUserNicknameUpdateToUser()
//INTER:
//HandleInterBroadcastForUser() -> _HandleInterBroadcastUserPrefs() -> _HandleInterBroadcastUserPrefsNickname()
//
static const UserPreferenceDescriptor prefs_table[] = {
#pragma region boolean prefs
        //master switch for roaming mode. If disabled, PREF_RM_WANDERER, PREF_RM_CONQUERER, PREF_RM_JOURNALER will be set to disabled as well. If enabled, then by default PREF_ROAMING_MODE will be enabled. User is free to change across the three types provided PREF_ROAMING_MODE switch is enabled.
        {PREF_ROAMING_MODE, 					  "roaming_mode", 	                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)PrefValidateGeoGroupsRoaming, (PreferenceValueFormatter) JsonValueFormatForRoamingMode,	.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_WANDERER, 					    "rm_wanderer", 		                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)PrefValidateGeoGroupsRoaming,  	(PreferenceValueFormatter)NULL, 																										.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_CONQUERER,					    "rm_conquerer", 	                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)PrefValidateGeoGroupsRoaming,  	(PreferenceValueFormatter)NULL, 																										.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_JOURNALER, 					  "rm_journaler", 	                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)PrefValidateGeoGroupsRoaming,  	(PreferenceValueFormatter)NULL, 																										.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_4, 				            "rm_7", 			                                PREFVALUETYPE_BOOL,      .value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_5,                     "rm_7", 					                            PREFVALUETYPE_BOOL, 		  .value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_6, 			              "rm_7", 					                            PREFVALUETYPE_BOOL, 		  .value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_7, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_8, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_9, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_10, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_11, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_12, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_13, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_14, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_15, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                           (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_16, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_17, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_18, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_19, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_20, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_21, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_22, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_23, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_24, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_25, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_26, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_27, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_28, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_29, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_30, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_31, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                            (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_32, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_33, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_34, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_35, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_36, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_37, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_38, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_39, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_40, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_41, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_42, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_43, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_44, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_45, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_46, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_47, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_48, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_49, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_50, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_51, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_52, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_53, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_54, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_55, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},

        {PREF_RM_56, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_57, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_58, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_59, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_60, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_61, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_62, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
        {PREF_RM_63, 									  "rm_7",		 				                            PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)NULL,                             (PreferenceValueFormatter)NULL,  																											.pref_ops=&prefs_ops_table[0]},
#pragma endregion

        //IMPORTANT string names must match what's stored in the DB under user_data json field (but not for sharelists, as they are fetched based on index)
        {PREF_NICKNAME, 								"nickname",		 				      PREFVALUETYPE_STR, 				.value={0}, (UserPreferenceValidate)_PrefValidateNickname,  (PreferenceValueFormatter)NULL,   														.pref_ops=&prefops_nickname},
        {PREF_AVATAR, 									"avatar",		 					      PREFVALUETYPE_STR, 				.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForUserAvatar, 				.pref_ops=&prefops_avatar},
        {PREF_SHLIST_PROFILE,/*66*/  	  "sharelist_profile",		    PREFVALUETYPE_BLOB, 			.value={0}, (UserPreferenceValidate) _PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForProfileShare,        .pref_ops=&prefops_sharelist_profile},
        {PREF_SHLIST_LOCATION, 				  "sharelist_location",	      PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForLocationShare, 			.pref_ops=&prefops_avatar},
        {PREF_SHLIST_CONTACTS,/*68*/		"sharelist_contacts",	      PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForContactsShare,        .pref_ops=&prefops_avatar},
        {PREF_SHLIST_NETSTATE,					"sharelist_netstate",	      PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForNetstateShare, 			.pref_ops=&prefops_avatar},
        {PREF_SHLIST_FRIENDS,/*70*/  	  "sharelist_friends",		    PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_BLOCKED,					  "sharelist_blocked",		    PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForBlockedShare, 				.pref_ops=&prefops_avatar},
        {PREF_SHLIST_READ_RECEIPT,			"sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForReadReceiptShare,		.pref_ops=&prefops_avatar},
        {PREF_SHLIST_ACTIVITY_STATE,    "sharelist_activity_state", PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																  .pref_ops=&prefops_avatar},
        {PREF_SHLIST_BLOCKED_FENCE,     "sharelist_blocked_fence",  PREFVALUETYPE_INT_MULTI,   .value={0}, (UserPreferenceValidate)_PrefValidateAvatar, (PreferenceValueFormatter) JsonValueFormatForBlockedFenceShare, 	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED2,/*75*/     "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED3,			      "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																  .pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED4,			      "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED5,			      "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																  .pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED6,			      "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,  (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED7,/*80*/     "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,                   (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},
        {PREF_SHLIST_UNUSED8,           "sharelist_read_receipt",   PREFVALUETYPE_INT_MULTI, 	.value={0}, (UserPreferenceValidate)_PrefValidateAvatar,                   (PreferenceValueFormatter)NULL, 																	.pref_ops=&prefops_avatar},

        //IMPORTANT string names must match what's stored in the DB under user_data json field (but not for sharelists, as they are fetched based on index)
        {PREF_E164NUMBER,/*82*/		      "e164number",               PREFVALUETYPE_STR, 				.value={0}, (UserPreferenceValidate)_PrefValidateE164Number, (PreferenceValueFormatter) JsonValueFormatForE164Number, 				.pref_ops=&prefops_e164number},
        {PREF_REGO_PIN,                 "rego_pin",                 PREFVALUETYPE_INT, 				.value={0}, (UserPreferenceValidate)_PrefValidateE164Number,               (PreferenceValueFormatter)NULL, 				                        .pref_ops=&prefs_ops_table[1]},
        {PREF_BASELOC_ANCHOR_ZONE,/*84*/"baseloc_zone",             PREFVALUETYPE_INT, 				.value={0}, (UserPreferenceValidate)_PrefValidateBaselocZone, (PreferenceValueFormatter) JsonValueFormatForGenericInteger, 		.pref_ops=&prefops_baseloc_zone},
        {PREF_GEOLOC_TRIGGER,/*85*/		  "geoloc_trigger",           PREFVALUETYPE_INT, 				.value={0}, (UserPreferenceValidate)_PrefValidateGeolocTrigger, (PreferenceValueFormatter) JsonValueFormatForGenericInteger, 	.pref_ops=&prefops_geoloc_trigger},
        {PREF_UNSOLICITED_CONTACT,      "unsolicited_contact",      PREFVALUETYPE_INT, 				.value={0}, (UserPreferenceValidate)_PrefValidateUnsolicitedContactAction, (PreferenceValueFormatter) JsonValueFormatForGenericInteger, 				.pref_ops=&prefs_ops_table[1]},
        {PREF_GUARDIAN_UID,             "guardian_uid",             PREFVALUETYPE_INT, 				.value={0}, (UserPreferenceValidate)_PrefValidateGuardianUid, (PreferenceValueFormatter) JsonValueFormatForGenericInteger, 				.pref_ops=&prefops_guardian_uid},
        {PREF_HOMEBASE_GEOLOC,          "homebase_geoloc",          PREFVALUETYPE_STR, 				.value={0}, (UserPreferenceValidate)_PrefValidateHomebaseGeoLoc, (PreferenceValueFormatter) JsonValueFormatForHomebaseGeoLoc, 				.pref_ops=&prefops_homebase_loc},

        {PREF_LAST_ALIGNMENT,            "",                                 PREFVALUETYPE_INVALID, 		.value={0}, NULL, 																					NULL, 																													.pref_ops=NULL}
};

#endif //UFSRV_DATA_USERPREFERENCEDESCRIPTOR_H
