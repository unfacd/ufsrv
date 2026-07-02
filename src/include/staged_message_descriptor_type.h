/**
 * Copyright (C) 2015-2024 unfacd works
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
#ifndef UFSRV_STAGED_MESSAGE_DESCRIPTOR_TYPE_H
#define UFSRV_STAGED_MESSAGE_DESCRIPTOR_TYPE_H

/**
 *  @struct StagedMessageDescriptor
 *  @brief Describe metadata params necessary to handle staged messages. Messages are cached in an "index store" and "payload store"
 *
 * @code
 * staged message index format:
 *  ZRANGE STAGED_OUTMSG_EVENTS:307 0 -1 => <%fid>"<%gid>
 * "434135037797990409:1160"
 * staged message payload:
    HGET STAGED_OUTMSG:307 "434135037797990409:1160" ==> "<%msg_sz>:<%encoded_msg>"
    @endcode
 */
typedef struct StagedMessageDescriptor {
    unsigned long gid; ///< ufsrv wide eid
    unsigned long eid; ///< msg event id
    unsigned long fid; ///< fence under which msg is staged
    unsigned long userid; ///< originating user id (sequenced)
} StagedMessageDescriptor;

#endif //UFSRV_STAGED_MESSAGE_DESCRIPTOR_TYPE_H
