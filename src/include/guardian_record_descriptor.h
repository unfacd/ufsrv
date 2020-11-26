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


#ifndef UFSRV_GUARDIAN_RECORD_DESCRIPTOR_H
#define UFSRV_GUARDIAN_RECORD_DESCRIPTOR_H

#include <session_type.h>

enum GuardianStatus {
  GUARDIAN_STATUS_NONE=0,
  GUARDIAN_STATUS_LINKED,
  GUARDIAN_STATUS_UNLINKED,
  GUARDIAN_STATUS_REQUESTED,
  GUARDIAN_STATUS_MUTED,
  GUARDIAN_STATUS_GUARDIAN
};

typedef struct GuardianRecordDescriptor {
  enum GuardianStatus			status;
  unsigned long long  		timestamp; //as recorded in the message header (millis)
  unsigned long           gid;
  struct {
    json_object *specs_jobj;
    char *specs_serialised; //
  } specs;
  struct { ;
    unsigned long uid;
    InstanceContextForSession *instance_ptr;
  } guardian;
  struct { ;
    unsigned long uid;
    InstanceContextForSession *instance_ptr;
  } originator;
} GuardianRecordDescriptor;


#endif //UFSRV_GUARDIAN_RECORD_DESCRIPTOR_H
