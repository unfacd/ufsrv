#!/usr/bin/env bash
HOST="`hostname | sed -e 's/\([a-zA-Z0-9\-]*\).*/\1/'`"
USER=`whoami`
HIM=$USER@$HOST
WHEN=`date | \
 awk '{ \
       if (NF==6) \
          { print $1 " "  $2 " " $3 " "  $6 " at " $4 " " $5 } \
       else \
         { print $1 " "  $2 " " $3 " " $7 " at " $4 " " $5 " " $6 }}'`

cat >version.c <<!END!
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

#include <version.h>
#include <main_types.h>

char *t_compiled="$WHEN";
char *u_compiled="$HIM";
char *ufsrv_version=STRINGISE(UFSRV_MAJOR)"."STRINGISE(UFSRV_MINOR)"."STRINGISE(UFSRV_PATCH);
!END!
