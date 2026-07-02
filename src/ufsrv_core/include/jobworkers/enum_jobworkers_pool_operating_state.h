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


#ifndef UFSRV_ENUM_JOBWORKERS_POOL_OPERATING_STATE_H
#define UFSRV_ENUM_JOBWORKERS_POOL_OPERATING_STATE_H

enum  JobWorkersPoolOperatingState {
  POOL_STATE_UNINITIALISED = 0,
  POOL_STATE_UP,
  POOL_STATE_SUSPENDED,
  POOL_STATE_DOWN
};

#endif //UFSRV_ENUM_JOBWORKERS_POOL_OPERATING_STATE_H
