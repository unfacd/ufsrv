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

//
// Created by devops on 10/21/20.
//

#ifndef UFSRVCORE_FENCE_PROTOBUF_H
#define UFSRVCORE_FENCE_PROTOBUF_H

#include <stdbool.h>
#include <attachment_descriptor_type.h>
#include <ufsrv_core/SignalService.pb-c.h>

AttachmentRecord *MakeAttachmentRecordInProto (AttachmentDescriptor *attachment_ptr, AttachmentRecord *attachment_record_ptr_out, bool flag_dup);
void DestructAttachmentRecord (AttachmentRecord  *attachment_record_ptr, bool flag_self_destruct);

#endif //UFSRV_FENCE_PROTOBUF_H
