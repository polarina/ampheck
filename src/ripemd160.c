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
#include "ripemd160.h"

#define RIPEMD160_R1(x, y, z)  (x ^ y ^ z)
#define RIPEMD160_R2(x, y, z)  (((x & y) | (~x & z)) + 0x5a827999)
#define RIPEMD160_R3(x, y, z)  (((x | ~y) ^ z)       + 0x6ed9eba1)
#define RIPEMD160_R4(x, y, z)  (((x & z) | (y & ~z)) + 0x8f1bbcdc)
#define RIPEMD160_R5(x, y, z)  ((x ^ (y | ~z))       + 0xa953fd4e)
#define RIPEMD160_R6(x, y, z)  ((x ^ (y | ~z))       + 0x50a28be6)
#define RIPEMD160_R7(x, y, z)  (((x & z) | (y & ~z)) + 0x5c4dd124)
#define RIPEMD160_R8(x, y, z)  (((x | ~y) ^ z)       + 0x6d703ef3)
#define RIPEMD160_R9(x, y, z)  (((x & y) | (~x & z)) + 0x7a6d76e9)
#define RIPEMD160_R10 RIPEMD160_R1

#define RIPEMD160_PRC(a, b, c, d, e, idx, rot, rnd) { \
	wv[a] = ROL(wv[a] + RIPEMD160_R##rnd(wv[b], wv[c], wv[d]) + idx, rot) + wv[e]; \
	wv[c] = ROL(wv[c], 10); \
}

void ampheck_ripemd160_init(struct ampheck_ripemd160 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;
	
	ctx->length = 0;
}

void ampheck_ripemd160_transform(struct ampheck_ripemd160 *ctx, const uint8_t *data, size_t blocks)
{
	for (size_t i = 0; i < blocks; ++i)
	{
		uint32_t wv[10];
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
		wv[4] = ctx->h[4];
		memcpy(&wv[5], wv, 5 * sizeof(uint32_t));
		
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 0], 11,  1);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 1], 14,  1);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 2], 15,  1);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 3], 12,  1);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 4],  5,  1);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 5],  8,  1);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 6],  7,  1);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 7],  9,  1);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 8], 11,  1);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 9], 13,  1);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[10], 14,  1);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[11], 15,  1);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[12],  6,  1);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[13],  7,  1);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[14],  9,  1);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[15],  8,  1);
		
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 7],  7,  2);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 4],  6,  2);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[13],  8,  2);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 1], 13,  2);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[10], 11,  2);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 6],  9,  2);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[15],  7,  2);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 3], 15,  2);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[12],  7,  2);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 0], 12,  2);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 9], 15,  2);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 5],  9,  2);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 2], 11,  2);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[14],  7,  2);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[11], 13,  2);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 8], 12,  2);
		
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 3], 11,  3);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[10], 13,  3);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[14],  6,  3);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 4],  7,  3);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 9], 14,  3);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[15],  9,  3);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 8], 13,  3);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 1], 15,  3);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 2], 14,  3);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 7],  8,  3);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 0], 13,  3);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 6],  6,  3);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[13],  5,  3);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[11], 12,  3);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 5],  7,  3);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[12],  5,  3);
		
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 1], 11,  4);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 9], 12,  4);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[11], 14,  4);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[10], 15,  4);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 0], 14,  4);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 8], 15,  4);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[12],  9,  4);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 4],  8,  4);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[13],  9,  4);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 3], 14,  4);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 7],  5,  4);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[15],  6,  4);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[14],  8,  4);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 5],  6,  4);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 6],  5,  4);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 2], 12,  4);
		
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 4],  9,  5);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 0], 15,  5);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[ 5],  5,  5);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 9], 11,  5);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 7],  6,  5);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[12],  8,  5);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 2], 13,  5);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[10], 12,  5);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[14],  5,  5);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[ 1], 12,  5);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[ 3], 13,  5);
		RIPEMD160_PRC(0, 1, 2, 3, 4, w[ 8], 14,  5);
		RIPEMD160_PRC(4, 0, 1, 2, 3, w[11], 11,  5);
		RIPEMD160_PRC(3, 4, 0, 1, 2, w[ 6],  8,  5);
		RIPEMD160_PRC(2, 3, 4, 0, 1, w[15],  5,  5);
		RIPEMD160_PRC(1, 2, 3, 4, 0, w[13],  6,  5);
		
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 5],  8,  6);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[14],  9,  6);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 7],  9,  6);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 0], 11,  6);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 9], 13,  6);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 2], 15,  6);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[11], 15,  6);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 4],  5,  6);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[13],  7,  6);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 6],  7,  6);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[15],  8,  6);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 8], 11,  6);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 1], 14,  6);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[10], 14,  6);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 3], 12,  6);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[12],  6,  6);
		
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 6],  9,  7);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[11], 13,  7);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 3], 15,  7);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 7],  7,  7);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 0], 12,  7);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[13],  8,  7);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 5],  9,  7);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[10], 11,  7);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[14],  7,  7);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[15],  7,  7);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 8], 12,  7);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[12],  7,  7);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 4],  6,  7);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 9], 15,  7);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 1], 13,  7);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 2], 11,  7);
		
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[15],  9,  8);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 5],  7,  8);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 1], 15,  8);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 3], 11,  8);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 7],  8,  8);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[14],  6,  8);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 6],  6,  8);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 9], 14,  8);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[11], 12,  8);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 8], 13,  8);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[12],  5,  8);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 2], 14,  8);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[10], 13,  8);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 0], 13,  8);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 4],  7,  8);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[13],  5,  8);
		
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 8], 15,  9);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 6],  5,  9);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 4],  8,  9);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 1], 11,  9);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 3], 14,  9);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[11], 14,  9);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[15],  6,  9);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 0], 14,  9);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 5],  6,  9);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[12],  9,  9);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 2], 12,  9);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[13],  9,  9);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 9], 12,  9);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 7],  5,  9);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[10], 15,  9);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[14],  8,  9);
		
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[12],  8, 10);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[15],  5, 10);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[10], 12, 10);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 4],  9, 10);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 1], 12, 10);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[ 5],  5, 10);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[ 8], 14, 10);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 7],  6, 10);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 6],  8, 10);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 2], 13, 10);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[13],  6, 10);
		RIPEMD160_PRC(5, 6, 7, 8, 9, w[14],  5, 10);
		RIPEMD160_PRC(9, 5, 6, 7, 8, w[ 0], 15, 10);
		RIPEMD160_PRC(8, 9, 5, 6, 7, w[ 3], 13, 10);
		RIPEMD160_PRC(7, 8, 9, 5, 6, w[ 9], 11, 10);
		RIPEMD160_PRC(6, 7, 8, 9, 5, w[11], 11, 10);
		
		wv[8] += wv[2] + ctx->h[1];
		ctx->h[1] = ctx->h[2] + wv[3] + wv[9];
		ctx->h[2] = ctx->h[3] + wv[4] + wv[5];
		ctx->h[3] = ctx->h[4] + wv[0] + wv[6];
		ctx->h[4] = ctx->h[0] + wv[1] + wv[7];
		ctx->h[0] = wv[8];
	}
}

void ampheck_ripemd160_update(struct ampheck_ripemd160 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);
		
		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;
		
		ampheck_ripemd160_transform(ctx, ctx->buffer, 1);
		ampheck_ripemd160_transform(ctx, data, size / 64);
		
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

void ampheck_ripemd160_finish(const struct ampheck_ripemd160 *ctx, uint8_t *digest)
{
	struct ampheck_ripemd160 tmp;
	
	memcpy(tmp.h, ctx->h, 5 * sizeof(uint32_t));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 64);
	
	tmp.buffer[ctx->length % 64] = 0x80;
	
	if (ctx->length % 64 < 56)
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 55 - ctx->length % 64);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 63 - ctx->length % 64);
		ampheck_ripemd160_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 56);
	}
	
	UNPACK_64_LE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_ripemd160_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_32_LE(tmp.h[0], &digest[ 0]);
	UNPACK_32_LE(tmp.h[1], &digest[ 4]);
	UNPACK_32_LE(tmp.h[2], &digest[ 8]);
	UNPACK_32_LE(tmp.h[3], &digest[12]);
	UNPACK_32_LE(tmp.h[4], &digest[16]);
}
