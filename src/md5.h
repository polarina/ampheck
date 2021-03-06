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

#ifndef ampheck_md5_h
#define ampheck_md5_h

#include <stddef.h>
#include <stdint.h>

struct ampheck_md5
{
	uint32_t h[4];
	uint8_t buffer[64];
	
	uint64_t length;
};

void ampheck_md5_init(struct ampheck_md5 *ctx);
void ampheck_md5_update(struct ampheck_md5 *ctx, const uint8_t *data, size_t length);
void ampheck_md5_finish(const struct ampheck_md5 *ctx, uint8_t *digest);

#endif
