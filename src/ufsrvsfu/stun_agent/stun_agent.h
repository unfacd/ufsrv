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

#ifndef UFSRV_STUN_AGENT_H
#define UFSRV_STUN_AGENT_H

#include <uflib/recycler/instance_type.h>
#include <host_name_descriptor_type.h>
#include <jobworkers/user_callback_job_descriptor_type.h>
#include <ufsrvsfu/stun_agent/stun_agent_type.h>
#include <ufsrvsfu/include/stun_server_type.h>
#include <ufsrvsfu/udp/re_udp.h>

typedef struct ICEAgentDescriptor {
  StunServer  *stun_server;
  StunAgent   stun_agent;
} ICEAgentDescriptor;

#define AS_ICE_AGENT_DESCRIPTOR(x) ((ICEAgentDescriptor *)(x))

UFSRVResult *ContactStunServer (ICEAgentDescriptor *ice_agent, InstanceHolder *instance_session);
int StunResponseHandler(InstanceHolderForSession *instance_session, enum IOHandlerEventStage event_stage);
UserCallbackJobDescriptor *BuildICEAgentJob (UserCallbackJobDescriptor *callback_job_descriptor_provided, InstanceHolder *);
ICEAgentDescriptor *BuildIceAgentDescriptor(ICEAgentDescriptor *ice_agent_descriptor_provided, bool is_fallback_stun_server);
const HostNameDescriptor *const GetFallbackStunServerHostName();
StunServer *GetFallbackStunServer(StunServer *stun_server_provided);
StunServer *GetEmptyStunServer(StunServer *stun_server_provided);

#endif //UFSRV_STUN_AGENT_H
