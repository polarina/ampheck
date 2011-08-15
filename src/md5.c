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
#include "md5.h"

#define MD5_R1(x, y, z) (z ^ (x & (y ^ z)))
#define MD5_R2(x, y, z) (y ^ (z & (x ^ y)))
#define MD5_R3(x, y, z) (x ^ y ^ z)
#define MD5_R4(x, y, z) (y ^ (x | ~z))

#define MD5_PRC(a, b, c, d, idx, rot, key, rnd) { \
	wv[a] = wv[b] + ROR(wv[a] + MD5_R##rnd(wv[b], wv[c], wv[d]) + key + idx, 32 - rot); \
}

void ampheck_md5_init(struct ampheck_md5 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	
	ctx->length = 0;
}

void ampheck_md5_transform(struct ampheck_md5 *ctx, const uint8_t *data, size_t blocks)
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
		
		MD5_PRC(0, 1, 2, 3, w[ 0],  7, 0xd76aa478, 1);
		MD5_PRC(3, 0, 1, 2, w[ 1], 12, 0xe8c7b756, 1);
		MD5_PRC(2, 3, 0, 1, w[ 2], 17, 0x242070db, 1);
		MD5_PRC(1, 2, 3, 0, w[ 3], 22, 0xc1bdceee, 1);
		MD5_PRC(0, 1, 2, 3, w[ 4],  7, 0xf57c0faf, 1);
		MD5_PRC(3, 0, 1, 2, w[ 5], 12, 0x4787c62a, 1);
		MD5_PRC(2, 3, 0, 1, w[ 6], 17, 0xa8304613, 1);
		MD5_PRC(1, 2, 3, 0, w[ 7], 22, 0xfd469501, 1);
		MD5_PRC(0, 1, 2, 3, w[ 8],  7, 0x698098d8, 1);
		MD5_PRC(3, 0, 1, 2, w[ 9], 12, 0x8b44f7af, 1);
		MD5_PRC(2, 3, 0, 1, w[10], 17, 0xffff5bb1, 1);
		MD5_PRC(1, 2, 3, 0, w[11], 22, 0x895cd7be, 1);
		MD5_PRC(0, 1, 2, 3, w[12],  7, 0x6b901122, 1);
		MD5_PRC(3, 0, 1, 2, w[13], 12, 0xfd987193, 1);
		MD5_PRC(2, 3, 0, 1, w[14], 17, 0xa679438e, 1);
		MD5_PRC(1, 2, 3, 0, w[15], 22, 0x49b40821, 1);
		
		MD5_PRC(0, 1, 2, 3, w[ 1],  5, 0xf61e2562, 2);
		MD5_PRC(3, 0, 1, 2, w[ 6],  9, 0xc040b340, 2);
		MD5_PRC(2, 3, 0, 1, w[11], 14, 0x265e5a51, 2);
		MD5_PRC(1, 2, 3, 0, w[ 0], 20, 0xe9b6c7aa, 2);
		MD5_PRC(0, 1, 2, 3, w[ 5],  5, 0xd62f105d, 2);
		MD5_PRC(3, 0, 1, 2, w[10],  9, 0x02441453, 2);
		MD5_PRC(2, 3, 0, 1, w[15], 14, 0xd8a1e681, 2);
		MD5_PRC(1, 2, 3, 0, w[ 4], 20, 0xe7d3fbc8, 2);
		MD5_PRC(0, 1, 2, 3, w[ 9],  5, 0x21e1cde6, 2);
		MD5_PRC(3, 0, 1, 2, w[14],  9, 0xc33707d6, 2);
		MD5_PRC(2, 3, 0, 1, w[ 3], 14, 0xf4d50d87, 2);
		MD5_PRC(1, 2, 3, 0, w[ 8], 20, 0x455a14ed, 2);
		MD5_PRC(0, 1, 2, 3, w[13],  5, 0xa9e3e905, 2);
		MD5_PRC(3, 0, 1, 2, w[ 2],  9, 0xfcefa3f8, 2);
		MD5_PRC(2, 3, 0, 1, w[ 7], 14, 0x676f02d9, 2);
		MD5_PRC(1, 2, 3, 0, w[12], 20, 0x8d2a4c8a, 2);
		
		MD5_PRC(0, 1, 2, 3, w[ 5],  4, 0xfffa3942, 3);
		MD5_PRC(3, 0, 1, 2, w[ 8], 11, 0x8771f681, 3);
		MD5_PRC(2, 3, 0, 1, w[11], 16, 0x6d9d6122, 3);
		MD5_PRC(1, 2, 3, 0, w[14], 23, 0xfde5380c, 3);
		MD5_PRC(0, 1, 2, 3, w[ 1],  4, 0xa4beea44, 3);
		MD5_PRC(3, 0, 1, 2, w[ 4], 11, 0x4bdecfa9, 3);
		MD5_PRC(2, 3, 0, 1, w[ 7], 16, 0xf6bb4b60, 3);
		MD5_PRC(1, 2, 3, 0, w[10], 23, 0xbebfbc70, 3);
		MD5_PRC(0, 1, 2, 3, w[13],  4, 0x289b7ec6, 3);
		MD5_PRC(3, 0, 1, 2, w[ 0], 11, 0xeaa127fa, 3);
		MD5_PRC(2, 3, 0, 1, w[ 3], 16, 0xd4ef3085, 3);
		MD5_PRC(1, 2, 3, 0, w[ 6], 23, 0x04881d05, 3);
		MD5_PRC(0, 1, 2, 3, w[ 9],  4, 0xd9d4d039, 3);
		MD5_PRC(3, 0, 1, 2, w[12], 11, 0xe6db99e5, 3);
		MD5_PRC(2, 3, 0, 1, w[15], 16, 0x1fa27cf8, 3);
		MD5_PRC(1, 2, 3, 0, w[ 2], 23, 0xc4ac5665, 3);
		
		MD5_PRC(0, 1, 2, 3, w[ 0],  6, 0xf4292244, 4);
		MD5_PRC(3, 0, 1, 2, w[ 7], 10, 0x432aff97, 4);
		MD5_PRC(2, 3, 0, 1, w[14], 15, 0xab9423a7, 4);
		MD5_PRC(1, 2, 3, 0, w[ 5], 21, 0xfc93a039, 4);
		MD5_PRC(0, 1, 2, 3, w[12],  6, 0x655b59c3, 4);
		MD5_PRC(3, 0, 1, 2, w[ 3], 10, 0x8f0ccc92, 4);
		MD5_PRC(2, 3, 0, 1, w[10], 15, 0xffeff47d, 4);
		MD5_PRC(1, 2, 3, 0, w[ 1], 21, 0x85845dd1, 4);
		MD5_PRC(0, 1, 2, 3, w[ 8],  6, 0x6fa87e4f, 4);
		MD5_PRC(3, 0, 1, 2, w[15], 10, 0xfe2ce6e0, 4);
		MD5_PRC(2, 3, 0, 1, w[ 6], 15, 0xa3014314, 4);
		MD5_PRC(1, 2, 3, 0, w[13], 21, 0x4e0811a1, 4);
		MD5_PRC(0, 1, 2, 3, w[ 4],  6, 0xf7537e82, 4);
		MD5_PRC(3, 0, 1, 2, w[11], 10, 0xbd3af235, 4);
		MD5_PRC(2, 3, 0, 1, w[ 2], 15, 0x2ad7d2bb, 4);
		MD5_PRC(1, 2, 3, 0, w[ 9], 21, 0xeb86d391, 4);
		
		ctx->h[0] += wv[0];
		ctx->h[1] += wv[1];
		ctx->h[2] += wv[2];
		ctx->h[3] += wv[3];
	}
}

void ampheck_md5_update(struct ampheck_md5 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);
		
		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;
		
		ampheck_md5_transform(ctx, ctx->buffer, 1);
		ampheck_md5_transform(ctx, data, size / 64);
		
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

void ampheck_md5_finish(const struct ampheck_md5 *ctx, uint8_t *digest)
{
	struct ampheck_md5 tmp;
	
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
		ampheck_md5_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 56);
	}
	
	UNPACK_64_LE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_md5_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_32_LE(tmp.h[0], &digest[ 0]);
	UNPACK_32_LE(tmp.h[1], &digest[ 4]);
	UNPACK_32_LE(tmp.h[2], &digest[ 8]);
	UNPACK_32_LE(tmp.h[3], &digest[12]);
}
