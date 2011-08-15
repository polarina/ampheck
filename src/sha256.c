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
#include "sha256.h"

#define CH(x, y, z) (z ^ (x & (y ^ z)))
#define MAJ(x, y, z) ((x & y) | (z & (x | y)))

#define SHA256_S0(x) (ROR(x,  7) ^ ROR(x, 18) ^ (x) >>  3)
#define SHA256_S1(x) (ROR(x, 17) ^ ROR(x, 19) ^ (x) >> 10)
#define SHA256_T0(x) (ROR(x,  2) ^ ROR(x, 13) ^ ROR(x, 22))
#define SHA256_T1(x) (ROR(x,  6) ^ ROR(x, 11) ^ ROR(x, 25))

#define SHA256_PRC(a, b, c, d, e, f, g, h, idx, key) { \
	uint32_t t1 = wv[h] + SHA256_T1(wv[e]) + CH(wv[e], wv[f], wv[g]) + key + idx; \
	wv[d] += t1; \
	wv[h]  = t1 + SHA256_T0(wv[a]) + MAJ(wv[a], wv[b], wv[c]); \
}

#define SHA256_EXT(i) ( \
	w[i] += SHA256_S0(w[(i + 1) & 0x0F]) + SHA256_S1(w[(i - 2) & 0x0F]) + w[(i - 7) & 0x0F] \
)

void ampheck_sha256_init(struct ampheck_sha256 *ctx)
{
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
	
	ctx->length = 0;
}

void ampheck_sha256_transform(struct ampheck_sha256 *ctx, const uint8_t *data, size_t blocks)
{
	for (size_t i = 0; i < blocks; ++i)
	{
		uint32_t wv[8];
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
		wv[5] = ctx->h[5];
		wv[6] = ctx->h[6];
		wv[7] = ctx->h[7];
		
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, w[ 0], 0x428a2f98);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, w[ 1], 0x71374491);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, w[ 2], 0xb5c0fbcf);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, w[ 3], 0xe9b5dba5);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, w[ 4], 0x3956c25b);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, w[ 5], 0x59f111f1);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, w[ 6], 0x923f82a4);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, w[ 7], 0xab1c5ed5);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, w[ 8], 0xd807aa98);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, w[ 9], 0x12835b01);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, w[10], 0x243185be);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, w[11], 0x550c7dc3);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, w[12], 0x72be5d74);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, w[13], 0x80deb1fe);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, w[14], 0x9bdc06a7);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, w[15], 0xc19bf174);
		
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 0), 0xe49b69c1);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 1), 0xefbe4786);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT( 2), 0x0fc19dc6);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT( 3), 0x240ca1cc);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT( 4), 0x2de92c6f);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT( 5), 0x4a7484aa);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT( 6), 0x5cb0a9dc);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT( 7), 0x76f988da);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 8), 0x983e5152);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 9), 0xa831c66d);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT(10), 0xb00327c8);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT(11), 0xbf597fc7);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT(12), 0xc6e00bf3);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT(13), 0xd5a79147);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT(14), 0x06ca6351);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT(15), 0x14292967);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 0), 0x27b70a85);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 1), 0x2e1b2138);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT( 2), 0x4d2c6dfc);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT( 3), 0x53380d13);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT( 4), 0x650a7354);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT( 5), 0x766a0abb);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT( 6), 0x81c2c92e);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT( 7), 0x92722c85);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 8), 0xa2bfe8a1);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 9), 0xa81a664b);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT(10), 0xc24b8b70);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT(11), 0xc76c51a3);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT(12), 0xd192e819);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT(13), 0xd6990624);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT(14), 0xf40e3585);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT(15), 0x106aa070);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 0), 0x19a4c116);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 1), 0x1e376c08);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT( 2), 0x2748774c);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT( 3), 0x34b0bcb5);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT( 4), 0x391c0cb3);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT( 5), 0x4ed8aa4a);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT( 6), 0x5b9cca4f);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT( 7), 0x682e6ff3);
		SHA256_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA256_EXT( 8), 0x748f82ee);
		SHA256_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA256_EXT( 9), 0x78a5636f);
		SHA256_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA256_EXT(10), 0x84c87814);
		SHA256_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA256_EXT(11), 0x8cc70208);
		SHA256_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA256_EXT(12), 0x90befffa);
		SHA256_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA256_EXT(13), 0xa4506ceb);
		SHA256_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA256_EXT(14), 0xbef9a3f7);
		SHA256_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA256_EXT(15), 0xc67178f2);
		
		ctx->h[0] += wv[0];
		ctx->h[1] += wv[1];
		ctx->h[2] += wv[2];
		ctx->h[3] += wv[3];
		ctx->h[4] += wv[4];
		ctx->h[5] += wv[5];
		ctx->h[6] += wv[6];
		ctx->h[7] += wv[7];
	}
}

void ampheck_sha256_update(struct ampheck_sha256 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);
		
		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;
		
		ampheck_sha256_transform(ctx, ctx->buffer, 1);
		ampheck_sha256_transform(ctx, data, size / 64);
		
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

void ampheck_sha256_finish(const struct ampheck_sha256 *ctx, uint8_t *digest)
{
	struct ampheck_sha256 tmp;
	
	memcpy(tmp.h, ctx->h, 8 * sizeof(uint32_t));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 64);
	
	tmp.buffer[ctx->length % 64] = 0x80;
	
	if (ctx->length % 64 < 56)
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 55 - ctx->length % 64);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 63 - ctx->length % 64);
		ampheck_sha256_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 56);
	}
	
	UNPACK_64_BE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_sha256_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_32_BE(tmp.h[0], &digest[ 0]);
	UNPACK_32_BE(tmp.h[1], &digest[ 4]);
	UNPACK_32_BE(tmp.h[2], &digest[ 8]);
	UNPACK_32_BE(tmp.h[3], &digest[12]);
	UNPACK_32_BE(tmp.h[4], &digest[16]);
	UNPACK_32_BE(tmp.h[5], &digest[20]);
	UNPACK_32_BE(tmp.h[6], &digest[24]);
	UNPACK_32_BE(tmp.h[7], &digest[28]);
}
