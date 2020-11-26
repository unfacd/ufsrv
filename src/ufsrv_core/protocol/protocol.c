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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrv_core/protocol/protocol.h>
#include <protocol_data.h>

 extern ufsrv *const masterptr;

//this shuld be decelared as extern by interested files to use
// const  ProtocolCallbacks *const protocol_callbacks=ProtocolCallbackWebsockets;
 const Protocol *const protocols_registry_ptr = ProtocolsRegistry;
 unsigned protocols_count = sizeof(ProtocolsRegistry) / sizeof(Protocol);

 void InitProtocols()
 {
	 //TODO: should load supported protocols from whatever is defined in the config file
	 //for the time being will make do with static initialisation.
	 syslog(LOG_INFO, "%s: INITIALISING SUPPORTED PROTOCOLS: Supporting %u protocols...", __func__, protocols_count-1);

	 Protocol *proto_ptr = &ProtocolsRegistry[masterptr->main_listener_protoid];

	 syslog(LOG_INFO, "%s: INITIALISING SUPPORTED PROTOCOL: '%s'...", __func__, PROTO_PROTOCOL_NAME(proto_ptr));

	 if (proto_ptr->protocol_callbacks.config_callback) {
		 (*proto_ptr->protocol_callbacks.config_callback)((ClientContextData *)masterptr->lua_ptr);
	 }

	 if ( proto_ptr->protocol_callbacks.protocol_init_callback) {
		 (*proto_ptr->protocol_callbacks.protocol_init_callback)(proto_ptr);
	 } else {
		 syslog(LOG_INFO, "%s: PROTOCOL: '%s' DID NOT REGISTER AN INIT CALL...", __func__,PROTO_PROTOCOL_NAME(proto_ptr));
	 }

//	 int i;
//	 for (i=0; i<protocols_count-1; i++)
//	 {
//		 Protocol *proto_ptr;
//		 proto_ptr=&ProtocolsRegistry[i];
//
//		 syslog(LOG_INFO, "%s: INITIALISING SUPPORTED PROTOCOL: '%s'...", __func__, PROTO_PROTOCOL_NAME(proto_ptr));
//
//		 if ( proto_ptr->protocol_callbacks.protocol_init_callback)
//		 {
//			 (*proto_ptr->protocol_callbacks.protocol_init_callback)(proto_ptr);
//		 }
//		 else
//		 {
//			 syslog(LOG_INFO, "%s: PROTOCOL: '%s' DID NOT REGISTER AN INIT CALL...", __func__,PROTO_PROTOCOL_NAME(proto_ptr));
//		 }
//	 }


 }

 __pure Protocol *ProtocolGet (unsigned protocol_id)
 {
	 if (protocol_id>protocols_count-1)	return NULL;

	 return &ProtocolsRegistry[protocol_id];
 }
