/**
 * Copyright (C) 2015-2021 unfacd works
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

#ifndef UFSRV_USER_CALLBACK_JOB_DESCRIPTOR_TYPE_H
#define UFSRV_USER_CALLBACK_JOB_DESCRIPTOR_TYPE_H

#include "uflib/recycler/instance_type.h"

#define AS_USER_CALLBACK_JOB_DESCRIPTOR(x) (UserCallbackJobDescriptor *)(x)
typedef void UserCallBackJobContext;
typedef void UserCallBackArgs;
typedef void UserCallBackReturnArgs;
typedef UserCallBackReturnArgs * (*user_callback)(UserCallBackArgs *, InstanceHolder *instance_session);
typedef void (*user_callback_on_error)(UserCallBackReturnArgs *);
typedef void (*user_callback_on_finish)(UserCallBackArgs *);

typedef struct UserCallbackJobDescriptor {
  user_callback handler;
  user_callback_on_finish finaliser;
  user_callback_on_error on_error_handler;
  UserCallBackArgs *callback_args;
  InstanceHolder *instance_session;
} UserCallbackJobDescriptor;

#endif //UFSRV_USER_CALLBACK_JOB_DESCRIPTOR_TYPE_H
