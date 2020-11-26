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

#ifndef UFSRV_UFSRV_INSTANCE_DESCRIPTOR_TYPE_H
#define UFSRV_UFSRV_INSTANCE_DESCRIPTOR_TYPE_H

typedef struct UfsrvInstanceDescriptor {
  int 				serverid;
  int 				serverid_by_user;
  int				ufsrv_geogroup;
  const char 			*server_class;
  const char 			*server_descriptive_name;
  unsigned long reqid;	//bit of a bolt on, should probably go somewhere else, but it relates to the context of a request served by instance
} UfsrvInstanceDescriptor;

#endif //UFSRV_UFSRV_INSTANCE_DESCRIPTOR_TYPE_H
