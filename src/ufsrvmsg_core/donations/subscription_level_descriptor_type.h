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

#ifndef UFSRV_SUBSCRIPTION_LEVEL_DESCRIPTOR_TYPE_H
#define UFSRV_SUBSCRIPTION_LEVEL_DESCRIPTOR_TYPE_H

typedef struct SubscriptionLevelDescriptor {
    int level_id;
    int state;
    struct {
        unsigned int amount;
        const char *currency_code;
    } price_info;
    char *product_id_processor,
         *price_id_processor;
} SubscriptionLevelDescriptor;

#endif //UFSRV_SUBSCRIPTION_LEVEL_DESCRIPTOR_TYPE_H
