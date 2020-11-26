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


#ifndef UFSRV_INCOMING_MESSAGE_DESCRIPTOR_TYPE_H
#define UFSRV_INCOMING_MESSAGE_DESCRIPTOR_TYPE_H

#include <time.h>
#include <ufsrv_instance_descriptor_type.h>

typedef struct IncomingMessageDescriptor {
  int											msg_type;
  time_t									timestamp; //as recorded in the message header
  unsigned long 					userid_from;
  unsigned long						fid;
  char       							*rawmsg;
  size_t									rawmsg_sz;
  UfsrvInstanceDescriptor *instance_descriptor_ptr;
  unsigned long           eid;
  unsigned long           gid;
} IncomingMessageDescriptor;

typedef struct IncomingMessageDescriptor ParsedMessageDescriptor;

#endif //UFSRV_INCOMING_MESSAGE_DESCRIPTOR_TYPE_H
