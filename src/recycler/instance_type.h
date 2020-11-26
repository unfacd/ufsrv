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

#ifndef UFSRV_INSTANCE_TYPE_H
#define UFSRV_INSTANCE_TYPE_H

#include <main_types.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

//classic tagged pointer implementation
//for pointer representation a 2bit tag is permissible
//pppppppp|pppppppp|pppppppp|pppppppp|pppppppp|pppppppp|pppppppp|pppppTT0
//^- actual pointer                                     two tag bits -^ ^- last bit 0
//for marshaller the last bit is turned on, thus only allowing for 63bit worth of value
//iiiiiiii|iiiiiiii|iiiiiiii|iiiiiiii|iiiiiiii|iiiiiiii|iiiiiiii|iiiiiii1
//^- actual marshaller                                                  ^- last bit 1
//isMarshaller: 1, isInstance:'0',  Marshaller value: 100
//isMarshalller: 0, isInstance:'1',  tag:'1', Type value: ayman

typedef uintptr_t MarshallerContextData;

typedef struct InstanceHolder {
  union {
    ClientContextData     *instance;
    MarshallerContextData marshaller; //instance marshaller id eg cid, fid etc...
  } holder;
} InstanceHolder;


//8-byte alignment. In the general case must be  > 1 to store a 2byte-aligned int
//In the general case should be power of 2: BYTE_ALIGNMENT != 0 && ((BYTE_ALIGNMENT & (BYTE_ALIGNMENT - 1)) == 0)
#define BYTE_ALIGNMENT 8

//for 8-byte alignment (8-1) aka 0b00000000000111
#define TAG_MASK (BYTE_ALIGNMENT-1)

#define INSTANCE_MASK (~TAG_MASK)

#define DEFAULT_TAG 1

inline static bool IsInstance (InstanceHolder *holder_ptr) {
  return (holder_ptr->holder.marshaller & 1) == 0;
}

inline static bool IsMarshaller (InstanceHolder *holder_ptr)  {
  return (holder_ptr->holder.marshaller & 1) == 1;
}

static inline void SetInstanceWithTag (InstanceHolder *holder_ptr, void *instance_ptr, uint8_t tag)
{
  // make sure that the pointer really is aligned
  assert(((uintptr_t)(instance_ptr) & TAG_MASK) == 0);

  // make sure that the tag isn't too large
  assert(((tag << 1) & INSTANCE_MASK) == 0);

  // last bit isn't part of tag anymore, but just zero, thus the << 1
  holder_ptr->holder.instance = instance_ptr;
  holder_ptr->holder.marshaller |= tag << 1;
}

static inline void SetInstance(InstanceHolder *holder_ptr, void *instance_ptr)
{
  SetInstanceWithTag(holder_ptr, instance_ptr, DEFAULT_TAG);
}

static inline void SetMarshaller(InstanceHolder *holder_ptr, uintptr_t number) {
  // make sure that when we << 1 there will be no data loss
  // i.e. make sure that it's a 31 bit / 63 bit integer
  assert(((number << 1) >> 1) == number);

  // shift the number to the left and set lowest bit to 1
  holder_ptr->holder.marshaller = (number << 1) | 1;
}

static inline void *GetInstance(InstanceHolder *holder_ptr)  {
#ifdef __UF_TESTING
  assert(IsInstance(holder_ptr));
#endif

  return (void *)(holder_ptr->holder.marshaller & INSTANCE_MASK);
}

static inline int GetTag (InstanceHolder *holder_ptr) {
#ifdef __UF_TESTING
  assert(IsInstance(holder_ptr));
#endif

  return (holder_ptr->holder.marshaller & TAG_MASK) >> 1;
}

static inline uintptr_t GetMarshaller (InstanceHolder *holder_ptr)  {
#ifdef __UF_TESTING
  assert(IsMarshaller(holder_ptr));
#endif

  return holder_ptr->holder.marshaller >> 1;
}

#endif //UFSRV_INSTANCE_TYPE_H
