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
#include "sha1.h"

#define SHA1_R1(x, y, z) ((z ^ (x & (y ^ z)))       + 0x5a827999)
#define SHA1_R2(x, y, z) ((x ^ y ^ z)               + 0x6ed9eba1)
#define SHA1_R3(x, y, z) (((x & y) | (z & (x | y))) + 0x8f1bbcdc)
#define SHA1_R4(x, y, z) ((x ^ y ^ z)               + 0xca62c1d6)

#define SHA1_PRC(a, b, c, d, e, idx, rnd) { \
	wv[e] += ROR(wv[a], 27) + SHA1_R##rnd(wv[b], wv[c], wv[d]) + idx; \
	wv[b]  = ROR(wv[b], 2); \
}

#define SHA1_EXT(i) ( \
	w[i] = ROR(w[(i - 3) & 0x0F] ^ w[(i - 8) & 0x0F] ^ w[(i - 14) & 0x0F] ^ w[i], 31) \
)

void ampheck_sha1_init(struct ampheck_sha1 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;
	
	ctx->length = 0;
}

void ampheck_sha1_transform(struct ampheck_sha1 *ctx, const uint8_t *data, size_t blocks)
{
	for (size_t i = 0; i < blocks; ++i)
	{
		uint32_t wv[5];
		uint32_t w[16];
		
		PACK_32_BE(&data[(i << 6)     ], &w[ 0]);
		PACK_32_BE(&data[(i << 6) +  4], &w[ 1]);
		PACK_32_BE(&data[(i << 6) +  8], &w[ 2]);
		PACK_32_BE(&data[(i << 6) + 12], &w[ 3]);
		PACK_32_BE(&data[(i << 6) + 16], &w[ 4]);
		PACK_32_BE(&data[(i << 6) + 20], &w[ 5]);
		PACK_32_BE(&data[(i << 6) + 24], &w[ 6]);
		PACK_32_BE(&data[(i << 6) + 28], &w[ 7]);
		PACK_32_BE(&data[(i << 6) + 32], &w[ 8]);
		PACK_32_BE(&data[(i << 6) + 36], &w[ 9]);
		PACK_32_BE(&data[(i << 6) + 40], &w[10]);
		PACK_32_BE(&data[(i << 6) + 44], &w[11]);
		PACK_32_BE(&data[(i << 6) + 48], &w[12]);
		PACK_32_BE(&data[(i << 6) + 52], &w[13]);
		PACK_32_BE(&data[(i << 6) + 56], &w[14]);
		PACK_32_BE(&data[(i << 6) + 60], &w[15]);
		
		wv[0] = ctx->h[0];
		wv[1] = ctx->h[1];
		wv[2] = ctx->h[2];
		wv[3] = ctx->h[3];
		wv[4] = ctx->h[4];
		
		SHA1_PRC(0, 1, 2, 3, 4, w[ 0], 1);
		SHA1_PRC(4, 0, 1, 2, 3, w[ 1], 1);
		SHA1_PRC(3, 4, 0, 1, 2, w[ 2], 1);
		SHA1_PRC(2, 3, 4, 0, 1, w[ 3], 1);
		SHA1_PRC(1, 2, 3, 4, 0, w[ 4], 1);
		SHA1_PRC(0, 1, 2, 3, 4, w[ 5], 1);
		SHA1_PRC(4, 0, 1, 2, 3, w[ 6], 1);
		SHA1_PRC(3, 4, 0, 1, 2, w[ 7], 1);
		SHA1_PRC(2, 3, 4, 0, 1, w[ 8], 1);
		SHA1_PRC(1, 2, 3, 4, 0, w[ 9], 1);
		SHA1_PRC(0, 1, 2, 3, 4, w[10], 1);
		SHA1_PRC(4, 0, 1, 2, 3, w[11], 1);
		SHA1_PRC(3, 4, 0, 1, 2, w[12], 1);
		SHA1_PRC(2, 3, 4, 0, 1, w[13], 1);
		SHA1_PRC(1, 2, 3, 4, 0, w[14], 1);
		SHA1_PRC(0, 1, 2, 3, 4, w[15], 1);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 0), 1);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 1), 1);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 2), 1);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 3), 1);
		
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 4), 2);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 5), 2);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 6), 2);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 7), 2);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 8), 2);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 9), 2);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT(10), 2);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT(11), 2);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT(12), 2);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT(13), 2);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT(14), 2);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT(15), 2);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 0), 2);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 1), 2);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 2), 2);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 3), 2);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 4), 2);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 5), 2);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 6), 2);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 7), 2);
		
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 8), 3);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 9), 3);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT(10), 3);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT(11), 3);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT(12), 3);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT(13), 3);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT(14), 3);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT(15), 3);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 0), 3);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 1), 3);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 2), 3);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 3), 3);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 4), 3);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 5), 3);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 6), 3);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 7), 3);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 8), 3);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 9), 3);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT(10), 3);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT(11), 3);
		
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT(12), 4);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT(13), 4);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT(14), 4);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT(15), 4);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 0), 4);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 1), 4);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 2), 4);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 3), 4);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 4), 4);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT( 5), 4);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT( 6), 4);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT( 7), 4);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT( 8), 4);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT( 9), 4);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT(10), 4);
		SHA1_PRC(0, 1, 2, 3, 4, SHA1_EXT(11), 4);
		SHA1_PRC(4, 0, 1, 2, 3, SHA1_EXT(12), 4);
		SHA1_PRC(3, 4, 0, 1, 2, SHA1_EXT(13), 4);
		SHA1_PRC(2, 3, 4, 0, 1, SHA1_EXT(14), 4);
		SHA1_PRC(1, 2, 3, 4, 0, SHA1_EXT(15), 4);
		
		ctx->h[0] += wv[0];
		ctx->h[1] += wv[1];
		ctx->h[2] += wv[2];
		ctx->h[3] += wv[3];
		ctx->h[4] += wv[4];
	}
}

void ampheck_sha1_update(struct ampheck_sha1 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);
		
		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;
		
		ampheck_sha1_transform(ctx, ctx->buffer, 1);
		ampheck_sha1_transform(ctx, data, size / 64);
		
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

void ampheck_sha1_finish(const struct ampheck_sha1 *ctx, uint8_t *digest)
{
	struct ampheck_sha1 tmp;
	
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
		ampheck_sha1_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 56);
	}
	
	UNPACK_64_BE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_sha1_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_32_BE(tmp.h[0], &digest[ 0]);
	UNPACK_32_BE(tmp.h[1], &digest[ 4]);
	UNPACK_32_BE(tmp.h[2], &digest[ 8]);
	UNPACK_32_BE(tmp.h[3], &digest[12]);
	UNPACK_32_BE(tmp.h[4], &digest[16]);
}
