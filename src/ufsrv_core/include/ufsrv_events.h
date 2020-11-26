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


#ifndef UFSRV_UFSRV_EVENTS_H
#define UFSRV_UFSRV_EVENTS_H

#include <ufsrvresult_type.h>
#include <ufsrv_core/fence/fence_event_type.h>

UFSRVResult *DbBackendGetEventDescriptorByGid (UfsrvEventDescriptor *event_descriptor_ptr_out);

#endif //UFSRV_UFSRV_EVENTS_H
