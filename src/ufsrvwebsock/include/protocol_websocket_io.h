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

#ifndef SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_
#define SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_

#include <ufsrvresult_type.h>
#include <recycler/instance_type.h>
#include <transmission_message_type.h>

int ReadFromSocketRaw (Session *sesnptr, SocketMessage *);

UFSRVResult *ProcessIncomingWsHandshake (Session *, SocketMessage *);
UFSRVResult *ProcessOutgoingWsHandshake (InstanceHolderForSession *, SocketMessage *);
UFSRVResult *ProcessIncomingWsHandshakeAsClient (Session *sesnptr, SocketMessage *sock_msg_ptr);
char *io_error (int error);

#endif /* SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_ */
