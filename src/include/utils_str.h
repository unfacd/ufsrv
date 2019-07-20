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

#ifndef SRC_INCLUDE_UTILS_STR_H_
#define SRC_INCLUDE_UTILS_STR_H_

int ftoa(char *outbuf, float f);
char *ultoa(unsigned long value, char *ptr, int base);
int itoa(char *ptr, uint32_t number);
unsigned digits_count (uint64_t number, unsigned base);

//_convenient_ macro to stringify on the fly without having to worry about dynamic allocation.
#define get_buffer_size(...) (snprintf(NULL, 0, __VA_ARGS__) + 1)
#define STRINGIFY_PARAMETER(...) sprintf_provided_buffer(alloca(get_buffer_size(__VA_ARGS__)), __VA_ARGS__)

char *sprintf_provided_buffer (char *user_allocated_buffer, char *format, ...);

#endif /* SRC_INCLUDE_UTILS_STR_H_ */
