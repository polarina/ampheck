/*
	Copyright (C) 2009  Gabriel A. Petursson
	
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef ampheck_sha224_h
#define ampheck_sha224_h

#include <stddef.h>
#include <stdint.h>

struct ampheck_sha224
{
	uint32_t h[8];
	uint8_t buffer[64];
	
	uint64_t length;
};

void ampheck_sha224_init(struct ampheck_sha224 *ctx);
void ampheck_sha224_update(struct ampheck_sha224 *ctx, const uint8_t *data, size_t length);
void ampheck_sha224_finish(const struct ampheck_sha224 *ctx, uint8_t *digest);

#endif
