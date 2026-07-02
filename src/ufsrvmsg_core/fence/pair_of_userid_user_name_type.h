/**
 * Copyright (C) 2015-2025 unfacd works
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

#ifndef UFSRV_PAIR_OF_USERID_USER_NAME_TYPE_H
#define UFSRV_PAIR_OF_USERID_USER_NAME_TYPE_H

typedef struct PairOfUserIdUserName {
    unsigned long 	uid;
    char *					uname;
    char *					aux;//whatever is remained after parsing
} PairOfUserIdUserName;

#endif //UFSRV_PAIR_OF_USERID_USER_NAME_TYPE_H
