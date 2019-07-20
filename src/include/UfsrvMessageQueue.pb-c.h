/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: UfsrvMessageQueue.proto */

#ifndef PROTOBUF_C_UfsrvMessageQueue_2eproto__INCLUDED
#define PROTOBUF_C_UfsrvMessageQueue_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "SignalService.pb-c.h"

typedef struct _SessionMessage SessionMessage;
typedef struct _SessionMessage__GeoFence SessionMessage__GeoFence;
typedef struct _MessageQueueMessage MessageQueueMessage;


/* --- enums --- */

/*
 *session event type
 */
typedef enum _SessionMessage__Status {
  SESSION_MESSAGE__STATUS__QUIT = 0,
  SESSION_MESSAGE__STATUS__CONNECTED = 1,
  SESSION_MESSAGE__STATUS__SUSPENDED = 2,
  /*
   *associated with account removal
   */
  SESSION_MESSAGE__STATUS__INVALIDTED = 3,
  SESSION_MESSAGE__STATUS__HEARTBEAT = 4,
  SESSION_MESSAGE__STATUS__PREFERENCE = 5,
  /*
   *change in geogroup assignment for the user (roaming mode has to be enabled)
   */
  SESSION_MESSAGE__STATUS__GEOFENCED = 6,
  /*
   *cache reset
   */
  SESSION_MESSAGE__STATUS__REBOOTED = 7
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SESSION_MESSAGE__STATUS)
} SessionMessage__Status;
typedef enum _MessageQueueMessage__BroadcastSemantics {
  /*
   *pure INTER broadcast	receiver only modify local data model
   */
  MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER = 0,
  /*
   *pure INTRA broadcast	receiver expected to change backend data model
   */
  MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA = 1,
  /*
   *broadcast from outside server class Backend data model has already taken place, therefore treat message with INTER semantics
   */
  MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA_WITH_INTER_SEMANTICS = 2,
  MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER_WITH_INTRA_SEMANTICS = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS)
} MessageQueueMessage__BroadcastSemantics;

/* --- messages --- */

struct  _SessionMessage__GeoFence
{
  ProtobufCMessage base;
  protobuf_c_boolean has_geofence_current;
  uint64_t geofence_current;
  protobuf_c_boolean has_geofence_past;
  uint64_t geofence_past;
};
#define SESSION_MESSAGE__GEO_FENCE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&session_message__geo_fence__descriptor) \
    , 0, 0, 0, 0 }


struct  _SessionMessage
{
  ProtobufCMessage base;
  uint64_t target_session;
  SessionMessage__Status status;
  /*
   *fences affected by this SessionMessage
   */
  size_t n_fences;
  FenceRecord **fences;
  /*
   *fences for which user invited  affected by this SessionMessage
   */
  size_t n_fences_invited;
  FenceRecord **fences_invited;
  /*
   *fences in which user blocked affected by this SessionMessage
   */
  size_t n_fences_blocked;
  FenceRecord **fences_blocked;
  size_t n_prefs;
  UserPreference **prefs;
  /*
   *for each fence -> collection of prefs, complementary to prefs above
   */
  size_t n_fence_prefs;
  FenceUserPreference **fence_prefs;
  SessionMessage__GeoFence *geo_fence;
  CommandHeader *header;
};
#define SESSION_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&session_message__descriptor) \
    , 0, SESSION_MESSAGE__STATUS__QUIT, 0,NULL, 0,NULL, 0,NULL, 0,NULL, 0,NULL, NULL, NULL }


struct  _MessageQueueMessage
{
  ProtobufCMessage base;
  /*
   *originating server
   */
  uint32_t origin;
  /*
   *the ufsrv instance for which the message is targeted
   */
  protobuf_c_boolean has_target_ufsrv;
  uint32_t target_ufsrv;
  /*
   */
  protobuf_c_boolean has_command_type;
  uint32_t command_type;
  /*
   *username remove onece its processed in SignaServce proto
   */
  protobuf_c_boolean has_ufsrvuid;
  ProtobufCBinaryData ufsrvuid;
  char *storage_id;
  protobuf_c_boolean has_broadcast_semantics;
  MessageQueueMessage__BroadcastSemantics broadcast_semantics;
  /*
   *request id generated when ufsrv instance was chosen
   */
  protobuf_c_boolean has_ufsrv_req_id;
  uint64_t ufsrv_req_id;
  /*
   *geogroup id targetd for handling message
   */
  protobuf_c_boolean has_geogroup_id;
  uint32_t geogroup_id;
  /*
   *original data message
   */
  DataMessage *wire_data;
  FenceCommand *fence;
  MessageCommand *message;
  LocationCommand *location;
  SessionMessage *session;
  UserCommand *user;
};
#define MESSAGE_QUEUE_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&message_queue_message__descriptor) \
    , 0, 0, 0, 0, 0, 0, {0,NULL}, NULL, 0, MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL }


/* SessionMessage__GeoFence methods */
void   session_message__geo_fence__init
                     (SessionMessage__GeoFence         *message);
/* SessionMessage methods */
void   session_message__init
                     (SessionMessage         *message);
size_t session_message__get_packed_size
                     (const SessionMessage   *message);
size_t session_message__pack
                     (const SessionMessage   *message,
                      uint8_t             *out);
size_t session_message__pack_to_buffer
                     (const SessionMessage   *message,
                      ProtobufCBuffer     *buffer);
SessionMessage *
       session_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   session_message__free_unpacked
                     (SessionMessage *message,
                      ProtobufCAllocator *allocator);
/* MessageQueueMessage methods */
void   message_queue_message__init
                     (MessageQueueMessage         *message);
size_t message_queue_message__get_packed_size
                     (const MessageQueueMessage   *message);
size_t message_queue_message__pack
                     (const MessageQueueMessage   *message,
                      uint8_t             *out);
size_t message_queue_message__pack_to_buffer
                     (const MessageQueueMessage   *message,
                      ProtobufCBuffer     *buffer);
MessageQueueMessage *
       message_queue_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   message_queue_message__free_unpacked
                     (MessageQueueMessage *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*SessionMessage__GeoFence_Closure)
                 (const SessionMessage__GeoFence *message,
                  void *closure_data);
typedef void (*SessionMessage_Closure)
                 (const SessionMessage *message,
                  void *closure_data);
typedef void (*MessageQueueMessage_Closure)
                 (const MessageQueueMessage *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor session_message__descriptor;
extern const ProtobufCMessageDescriptor session_message__geo_fence__descriptor;
extern const ProtobufCEnumDescriptor    session_message__status__descriptor;
extern const ProtobufCMessageDescriptor message_queue_message__descriptor;
extern const ProtobufCEnumDescriptor    message_queue_message__broadcast_semantics__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_UfsrvMessageQueue_2eproto__INCLUDED */
