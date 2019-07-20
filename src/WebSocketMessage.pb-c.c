/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: WebSocketMessage.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "WebSocketMessage.pb-c.h"
void   web_socket_request_message__init
                     (WebSocketRequestMessage         *message)
{
  static WebSocketRequestMessage init_value = WEB_SOCKET_REQUEST_MESSAGE__INIT;
  *message = init_value;
}
size_t web_socket_request_message__get_packed_size
                     (const WebSocketRequestMessage *message)
{
  assert(message->base.descriptor == &web_socket_request_message__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t web_socket_request_message__pack
                     (const WebSocketRequestMessage *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &web_socket_request_message__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t web_socket_request_message__pack_to_buffer
                     (const WebSocketRequestMessage *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &web_socket_request_message__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
WebSocketRequestMessage *
       web_socket_request_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (WebSocketRequestMessage *)
     protobuf_c_message_unpack (&web_socket_request_message__descriptor,
                                allocator, len, data);
}
void   web_socket_request_message__free_unpacked
                     (WebSocketRequestMessage *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &web_socket_request_message__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   web_socket_response_message__init
                     (WebSocketResponseMessage         *message)
{
  static WebSocketResponseMessage init_value = WEB_SOCKET_RESPONSE_MESSAGE__INIT;
  *message = init_value;
}
size_t web_socket_response_message__get_packed_size
                     (const WebSocketResponseMessage *message)
{
  assert(message->base.descriptor == &web_socket_response_message__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t web_socket_response_message__pack
                     (const WebSocketResponseMessage *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &web_socket_response_message__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t web_socket_response_message__pack_to_buffer
                     (const WebSocketResponseMessage *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &web_socket_response_message__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
WebSocketResponseMessage *
       web_socket_response_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (WebSocketResponseMessage *)
     protobuf_c_message_unpack (&web_socket_response_message__descriptor,
                                allocator, len, data);
}
void   web_socket_response_message__free_unpacked
                     (WebSocketResponseMessage *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &web_socket_response_message__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   web_socket_message__init
                     (WebSocketMessage         *message)
{
  static WebSocketMessage init_value = WEB_SOCKET_MESSAGE__INIT;
  *message = init_value;
}
size_t web_socket_message__get_packed_size
                     (const WebSocketMessage *message)
{
  assert(message->base.descriptor == &web_socket_message__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t web_socket_message__pack
                     (const WebSocketMessage *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &web_socket_message__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t web_socket_message__pack_to_buffer
                     (const WebSocketMessage *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &web_socket_message__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
WebSocketMessage *
       web_socket_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (WebSocketMessage *)
     protobuf_c_message_unpack (&web_socket_message__descriptor,
                                allocator, len, data);
}
void   web_socket_message__free_unpacked
                     (WebSocketMessage *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &web_socket_message__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor web_socket_request_message__field_descriptors[4] =
{
  {
    "verb",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(WebSocketRequestMessage, verb),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "path",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(WebSocketRequestMessage, path),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "body",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(WebSocketRequestMessage, has_body),
    offsetof(WebSocketRequestMessage, body),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "id",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(WebSocketRequestMessage, has_id),
    offsetof(WebSocketRequestMessage, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned web_socket_request_message__field_indices_by_name[] = {
  2,   /* field[2] = body */
  3,   /* field[3] = id */
  1,   /* field[1] = path */
  0,   /* field[0] = verb */
};
static const ProtobufCIntRange web_socket_request_message__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor web_socket_request_message__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "WebSocketRequestMessage",
  "WebSocketRequestMessage",
  "WebSocketRequestMessage",
  "",
  sizeof(WebSocketRequestMessage),
  4,
  web_socket_request_message__field_descriptors,
  web_socket_request_message__field_indices_by_name,
  1,  web_socket_request_message__number_ranges,
  (ProtobufCMessageInit) web_socket_request_message__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor web_socket_response_message__field_descriptors[4] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(WebSocketResponseMessage, has_id),
    offsetof(WebSocketResponseMessage, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "status",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(WebSocketResponseMessage, has_status),
    offsetof(WebSocketResponseMessage, status),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "message",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(WebSocketResponseMessage, message),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "body",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(WebSocketResponseMessage, has_body),
    offsetof(WebSocketResponseMessage, body),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned web_socket_response_message__field_indices_by_name[] = {
  3,   /* field[3] = body */
  0,   /* field[0] = id */
  2,   /* field[2] = message */
  1,   /* field[1] = status */
};
static const ProtobufCIntRange web_socket_response_message__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor web_socket_response_message__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "WebSocketResponseMessage",
  "WebSocketResponseMessage",
  "WebSocketResponseMessage",
  "",
  sizeof(WebSocketResponseMessage),
  4,
  web_socket_response_message__field_descriptors,
  web_socket_response_message__field_indices_by_name,
  1,  web_socket_response_message__number_ranges,
  (ProtobufCMessageInit) web_socket_response_message__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue web_socket_message__type__enum_values_by_number[3] =
{
  { "UNKNOWN", "WEB_SOCKET_MESSAGE__TYPE__UNKNOWN", 0 },
  { "REQUEST", "WEB_SOCKET_MESSAGE__TYPE__REQUEST", 1 },
  { "RESPONSE", "WEB_SOCKET_MESSAGE__TYPE__RESPONSE", 2 },
};
static const ProtobufCIntRange web_socket_message__type__value_ranges[] = {
{0, 0},{0, 3}
};
static const ProtobufCEnumValueIndex web_socket_message__type__enum_values_by_name[3] =
{
  { "REQUEST", 1 },
  { "RESPONSE", 2 },
  { "UNKNOWN", 0 },
};
const ProtobufCEnumDescriptor web_socket_message__type__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "WebSocketMessage.Type",
  "Type",
  "WebSocketMessage__Type",
  "",
  3,
  web_socket_message__type__enum_values_by_number,
  3,
  web_socket_message__type__enum_values_by_name,
  1,
  web_socket_message__type__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
static const ProtobufCFieldDescriptor web_socket_message__field_descriptors[4] =
{
  {
    "type",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    offsetof(WebSocketMessage, has_type),
    offsetof(WebSocketMessage, type),
    &web_socket_message__type__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "command",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(WebSocketMessage, command),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "request",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(WebSocketMessage, request),
    &web_socket_request_message__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "response",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(WebSocketMessage, response),
    &web_socket_response_message__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned web_socket_message__field_indices_by_name[] = {
  1,   /* field[1] = command */
  2,   /* field[2] = request */
  3,   /* field[3] = response */
  0,   /* field[0] = type */
};
static const ProtobufCIntRange web_socket_message__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor web_socket_message__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "WebSocketMessage",
  "WebSocketMessage",
  "WebSocketMessage",
  "",
  sizeof(WebSocketMessage),
  4,
  web_socket_message__field_descriptors,
  web_socket_message__field_indices_by_name,
  1,  web_socket_message__number_ranges,
  (ProtobufCMessageInit) web_socket_message__init,
  NULL,NULL,NULL    /* reserved[123] */
};
