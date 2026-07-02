/**
 * Copyright (C) 2015-2024 unfacd works
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

#ifndef UFSRV_INTEGRITY_VERDICT_DESCRIPTOR_TYPE_H
#define UFSRV_INTEGRITY_VERDICT_DESCRIPTOR_TYPE_H

//As mapped from google verdic response
enum IntegrityVerdict {
    MEETS_APP_INTEGRITY,
    MEETS_DEVICE_INTEGRITY
};

struct IntegrityVerdictDescriptor {
    enum IntegrityVerdict device_verdict;
    enum IntegrityVerdict app_verdict;
    char *request_hash; //? as provided by client user
};
typedef struct IntegrityVerdictDescriptor  IntegrityVerdictDescriptor;

#endif //UFSRV_INTEGRITY_VERDICT_DESCRIPTOR_TYPE_H
