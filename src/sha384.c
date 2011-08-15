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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ampheck.h"
#include "sha384.h"
#include "sha512.h"

void ampheck_sha384_init(struct ampheck_sha384 *ctx)
{
	ctx->h[0] = 0xcbbb9d5dc1059ed8;
	ctx->h[1] = 0x629a292a367cd507;
	ctx->h[2] = 0x9159015a3070dd17;
	ctx->h[3] = 0x152fecd8f70e5939;
	ctx->h[4] = 0x67332667ffc00b31;
	ctx->h[5] = 0x8eb44a8768581511;
	ctx->h[6] = 0xdb0c2e0d64f98fa7;
	ctx->h[7] = 0x47b5481dbefa4fa4;
	
	ctx->length = 0;
}

void ampheck_sha384_update(struct ampheck_sha384 *ctx, const uint8_t *data, size_t size)
{
	struct ampheck_sha512 context;
	
	memcpy(context.h,      ctx->h,       8 * sizeof(uint64_t));
	memcpy(context.buffer, ctx->buffer, 64 * sizeof(uint8_t));
	context.length = ctx->length;
	
	ampheck_sha512_update(&context, data, size);
	
	memcpy(ctx->h,      context.h,       8 * sizeof(uint64_t));
	memcpy(ctx->buffer, context.buffer, 64 * sizeof(uint8_t));
	ctx->length = context.length;
}

void ampheck_sha384_finish(const struct ampheck_sha384 *ctx, uint8_t *digest)
{
	uint8_t final[64];
	struct ampheck_sha512 context;
	
	memcpy(context.h,      ctx->h,       8 * sizeof(uint64_t));
	memcpy(context.buffer, ctx->buffer, 64 * sizeof(uint8_t));
	context.length = ctx->length;
	
	ampheck_sha512_finish(&context, final);
	
	memcpy(digest, final, 48);
}
