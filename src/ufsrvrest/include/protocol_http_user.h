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

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_USER_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_USER_H_

#include <ufsrvresult_type.h>
#include <session_type.h>
#include <ufsrvuid_type.h>
#include <fence.h>

UFSRVResult *DeactivateUserAndPropogate (Session *sesn_ptr, UfsrvUid *, bool flag_nuke);
int SendVerificationSms (Session *sesn_ptr, const char *, VerificationCode *vcode_ptr, bool android_sms_retriever_flag);
int SendVerificationVoice (Session *sesn_ptr, const char *destination, VerificationCode *vcode_ptr);
int SendVerificationEmail(Session *sesn_ptr, const char *to_email, const PendingAccount *);

#endif /* SRC_INCLUDE_PROTOCOL_HTTP_USER_H_ */
