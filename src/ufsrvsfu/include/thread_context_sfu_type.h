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


#ifndef UFSRV_THREADCONTEXTSFU_H
#define UFSRV_THREADCONTEXTSFU_H

#include <pthread.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <uflib/db/db_sql.h>

typedef struct ThreadContextSfu {
  InstrumentationBackend 	instrumentation_backend;
  DbBackend 							*db_backend;

  //todo these are temporary, as some legacy code still expect them to be defined
  pthread_key_t ufsrv_instrumentation_backend_key;
  pthread_key_t ufsrv_db_backend_key;
} ThreadContextSfu;

#endif //UFSRV_THREADCONTEXTSFU_H
