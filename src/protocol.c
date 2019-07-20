/*


    Copyright (C) 1999-2001  Ayman Akt

 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <protocol.h>
#include <nportredird.h>
#include <protocol_data.h>


 /* encapsulates all global variables */
 extern ufsrv *const masterptr;

//this shuld be decelared as extern by interested files to use
// const  ProtocolCallbacks *const protocol_callbacks=ProtocolCallbackWebsockets;
 const Protocol *const protocols_registry_ptr=ProtocolsRegistry;
 unsigned protocols_count=sizeof(ProtocolsRegistry)/sizeof(Protocol);


 void InitProtocols ()
 {
	 //TODO: should load supported protocols from whatever is defined in the config file
	 //for the time being will make do with static initialisation.
	 syslog(LOG_INFO, "%s: INITIALISING SUPPORTED PROTOCOLS: Supporting %u protocols...", __func__, protocols_count-1);

	 Protocol *proto_ptr;
	 proto_ptr=&ProtocolsRegistry[masterptr->main_listener_protoid];

	 syslog(LOG_INFO, "%s: INITIALISING SUPPORTED PROTOCOL: '%s'...", __func__, PROTO_PROTOCOL_NAME(proto_ptr));

	 if (proto_ptr->protocol_callbacks.config_callback)
	 {
		 (*proto_ptr->protocol_callbacks.config_callback)((ClientContextData *)masterptr->lua_ptr);
	 }

	 if ( proto_ptr->protocol_callbacks.protocol_init_callback)
	 {
		 (*proto_ptr->protocol_callbacks.protocol_init_callback)(proto_ptr);
	 }
	 else
	 {
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
