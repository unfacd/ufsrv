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

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_IO_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_IO_H_

#include <recycler/instance_type.h>
#include <ufsrvresult_type.h>
#include <transmission_message_type.h>
#include <session.h>

ssize_t ReadFromSocket (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned flag);

int SendTextMessage (InstanceHolderForSession *, const char *msg, size_t msglen);

ssize_t SendToSocket (InstanceHolderForSession *, TransmissionMessage *tmsg_ptr, unsigned flag);
int DispatchSocketMessageQueue (InstanceHolderForSession *, size_t entries);

UFSRVResult *ConsolidateSocketMessageQueue (Session *sesn_ptr, unsigned call_flags, UFSRVResult *);
void ErrorFromSocket (InstanceHolderForSession *instance_sesn_ptr, unsigned);

#endif /* SRC_INCLUDE_PROTOCOL_HTTP_IO_H_ */
