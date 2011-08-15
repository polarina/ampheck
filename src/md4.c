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
#include "md4.h"

#define MD4_R1(x, y, z) (z ^ (x & (y ^ z)))
#define MD4_R2(x, y, z) (((x & y) | (z & (x | y))) + 0x5a827999)
#define MD4_R3(x, y, z) ((x ^ y ^ z)               + 0x6ed9eba1)

#define MD4_PRC(a, b, c, d, idx, rot, rnd) { \
	wv[a] += MD4_R##rnd(wv[b], wv[c], wv[d]) + idx; \
	wv[a]  = ROR(wv[a], 32 - rot); \
}

void ampheck_md4_init(struct ampheck_md4 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	
	ctx->length = 0;
}

void ampheck_md4_transform(struct ampheck_md4 *ctx, const uint8_t *data, size_t blocks)
{
	for (size_t i = 0; i < blocks; ++i)
	{
		uint32_t wv[4];
		uint32_t w[16];
		
		PACK_32_LE(&data[(i << 6)     ], &w[ 0]);
		PACK_32_LE(&data[(i << 6) +  4], &w[ 1]);
		PACK_32_LE(&data[(i << 6) +  8], &w[ 2]);
		PACK_32_LE(&data[(i << 6) + 12], &w[ 3]);
		PACK_32_LE(&data[(i << 6) + 16], &w[ 4]);
		PACK_32_LE(&data[(i << 6) + 20], &w[ 5]);
		PACK_32_LE(&data[(i << 6) + 24], &w[ 6]);
		PACK_32_LE(&data[(i << 6) + 28], &w[ 7]);
		PACK_32_LE(&data[(i << 6) + 32], &w[ 8]);
		PACK_32_LE(&data[(i << 6) + 36], &w[ 9]);
		PACK_32_LE(&data[(i << 6) + 40], &w[10]);
		PACK_32_LE(&data[(i << 6) + 44], &w[11]);
		PACK_32_LE(&data[(i << 6) + 48], &w[12]);
		PACK_32_LE(&data[(i << 6) + 52], &w[13]);
		PACK_32_LE(&data[(i << 6) + 56], &w[14]);
		PACK_32_LE(&data[(i << 6) + 60], &w[15]);
		
		wv[0] = ctx->h[0];
		wv[1] = ctx->h[1];
		wv[2] = ctx->h[2];
		wv[3] = ctx->h[3];
		
		MD4_PRC(0, 1, 2, 3, w[ 0],  3, 1);
		MD4_PRC(3, 0, 1, 2, w[ 1],  7, 1);
		MD4_PRC(2, 3, 0, 1, w[ 2], 11, 1);
		MD4_PRC(1, 2, 3, 0, w[ 3], 19, 1);
		MD4_PRC(0, 1, 2, 3, w[ 4],  3, 1);
		MD4_PRC(3, 0, 1, 2, w[ 5],  7, 1);
		MD4_PRC(2, 3, 0, 1, w[ 6], 11, 1);
		MD4_PRC(1, 2, 3, 0, w[ 7], 19, 1);
		MD4_PRC(0, 1, 2, 3, w[ 8],  3, 1);
		MD4_PRC(3, 0, 1, 2, w[ 9],  7, 1);
		MD4_PRC(2, 3, 0, 1, w[10], 11, 1);
		MD4_PRC(1, 2, 3, 0, w[11], 19, 1);
		MD4_PRC(0, 1, 2, 3, w[12],  3, 1);
		MD4_PRC(3, 0, 1, 2, w[13],  7, 1);
		MD4_PRC(2, 3, 0, 1, w[14], 11, 1);
		MD4_PRC(1, 2, 3, 0, w[15], 19, 1);
		
		MD4_PRC(0, 1, 2, 3, w[ 0],  3, 2);
		MD4_PRC(3, 0, 1, 2, w[ 4],  5, 2);
		MD4_PRC(2, 3, 0, 1, w[ 8],  9, 2);
		MD4_PRC(1, 2, 3, 0, w[12], 13, 2);
		MD4_PRC(0, 1, 2, 3, w[ 1],  3, 2);
		MD4_PRC(3, 0, 1, 2, w[ 5],  5, 2);
		MD4_PRC(2, 3, 0, 1, w[ 9],  9, 2);
		MD4_PRC(1, 2, 3, 0, w[13], 13, 2);
		MD4_PRC(0, 1, 2, 3, w[ 2],  3, 2);
		MD4_PRC(3, 0, 1, 2, w[ 6],  5, 2);
		MD4_PRC(2, 3, 0, 1, w[10],  9, 2);
		MD4_PRC(1, 2, 3, 0, w[14], 13, 2);
		MD4_PRC(0, 1, 2, 3, w[ 3],  3, 2);
		MD4_PRC(3, 0, 1, 2, w[ 7],  5, 2);
		MD4_PRC(2, 3, 0, 1, w[11],  9, 2);
		MD4_PRC(1, 2, 3, 0, w[15], 13, 2);
		
		MD4_PRC(0, 1, 2, 3, w[ 0],  3, 3);
		MD4_PRC(3, 0, 1, 2, w[ 8],  9, 3);
		MD4_PRC(2, 3, 0, 1, w[ 4], 11, 3);
		MD4_PRC(1, 2, 3, 0, w[12], 15, 3);
		MD4_PRC(0, 1, 2, 3, w[ 2],  3, 3);
		MD4_PRC(3, 0, 1, 2, w[10],  9, 3);
		MD4_PRC(2, 3, 0, 1, w[ 6], 11, 3);
		MD4_PRC(1, 2, 3, 0, w[14], 15, 3);
		MD4_PRC(0, 1, 2, 3, w[ 1],  3, 3);
		MD4_PRC(3, 0, 1, 2, w[ 9],  9, 3);
		MD4_PRC(2, 3, 0, 1, w[ 5], 11, 3);
		MD4_PRC(1, 2, 3, 0, w[13], 15, 3);
		MD4_PRC(0, 1, 2, 3, w[ 3],  3, 3);
		MD4_PRC(3, 0, 1, 2, w[11],  9, 3);
		MD4_PRC(2, 3, 0, 1, w[ 7], 11, 3);
		MD4_PRC(1, 2, 3, 0, w[15], 15, 3);
		
		ctx->h[0] += wv[0];
		ctx->h[1] += wv[1];
		ctx->h[2] += wv[2];
		ctx->h[3] += wv[3];
	}
}

void ampheck_md4_update(struct ampheck_md4 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);
		
		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;
		
		ampheck_md4_transform(ctx, ctx->buffer, 1);
		ampheck_md4_transform(ctx, data, size / 64);
		
		data += size & ~63;
		size %= 64;
		
		memcpy(ctx->buffer, data, size);
	}
	else
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, size);
	}
	
	ctx->length += tmp;
}

void ampheck_md4_finish(const struct ampheck_md4 *ctx, uint8_t *digest)
{
	struct ampheck_md4 tmp;
	
	memcpy(tmp.h, ctx->h, 4 * sizeof(uint32_t));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 64);
	
	tmp.buffer[ctx->length % 64] = 0x80;
	
	if (ctx->length % 64 < 56)
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 55 - ctx->length % 64);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 63 - ctx->length % 64);
		ampheck_md4_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 56);
	}
	
	UNPACK_64_LE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_md4_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_32_LE(tmp.h[0], &digest[ 0]);
	UNPACK_32_LE(tmp.h[1], &digest[ 4]);
	UNPACK_32_LE(tmp.h[2], &digest[ 8]);
	UNPACK_32_LE(tmp.h[3], &digest[12]);
}
