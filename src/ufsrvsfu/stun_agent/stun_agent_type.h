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

//
// Created by devops on 6/27/21.
//

#include <ufsrvsfu/include/stun_server_type.h>
#include <ufsrvsfu/ice/re_ice.h>
#include <ufsrvsfu/stun/re_stun.h>

#include <ufsrvsfu/sa/sa.h>
#include <ufsrvsfu/udp/re_udp.h>
#include <re_dns.h>

#ifndef UFSRV_STUN_AGENT_TYPE_H
#define UFSRV_STUN_AGENT_TYPE_H

struct attrs {
  struct attr {
    char name[16];
    char value[128];
  } attrv[16];
  unsigned attrc;
};

typedef struct StunAgent {
  struct icem *icem;
  struct udp_sock *us;
  struct sa laddr;
  struct attrs attr_s;
  struct attrs attr_m;
//  struct ice_test *it;  /* parent */
  struct stunserver *stun;
  StunServer *stun_server;
  struct turnserver *turn;
  enum ice_mode mode;
  char name[16];
  uint8_t compid;
  bool offerer;
  bool use_turn;
  size_t n_cand;

  char lufrag[8];
  char lpwd[32];

  /* results: */
  bool gathering_ok;
  bool conncheck_ok;

  struct stun_ctrans *ct_gath;

  struct dnsc *dnsc;
  struct stun_dns *dns;
} StunAgent;

#endif //UFSRV_STUN_AGENT_TYPE_H
