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
#include "sha512.h"

#define CH(x, y, z) (z ^ (x & (y ^ z)))
#define MAJ(x, y, z) ((x & y) | (z & (x | y)))

#define SHA512_S0(x) (ROR(x,  1) ^ ROR(x,  8) ^ (x) >>  7)
#define SHA512_S1(x) (ROR(x, 19) ^ ROR(x, 61) ^ (x) >>  6)
#define SHA512_T0(x) (ROR(x, 28) ^ ROR(x, 34) ^ ROR(x, 39))
#define SHA512_T1(x) (ROR(x, 14) ^ ROR(x, 18) ^ ROR(x, 41))

#define SHA512_PRC(a, b, c, d, e, f, g, h, idx, key) { \
	uint64_t t1 = wv[h] + SHA512_T1(wv[e]) + CH(wv[e], wv[f], wv[g]) + key + idx; \
	wv[d] += t1; \
	wv[h]  = t1 + SHA512_T0(wv[a]) + MAJ(wv[a], wv[b], wv[c]); \
}

#define SHA512_EXT(i) ( \
	w[i] += SHA512_S0(w[(i + 1) & 0x0F]) + SHA512_S1(w[(i - 2) & 0x0F]) + w[(i - 7) & 0x0F] \
)

void ampheck_sha512_init(struct ampheck_sha512 *ctx)
{
	ctx->h[0] = 0x6a09e667f3bcc908;
	ctx->h[1] = 0xbb67ae8584caa73b;
	ctx->h[2] = 0x3c6ef372fe94f82b;
	ctx->h[3] = 0xa54ff53a5f1d36f1;
	ctx->h[4] = 0x510e527fade682d1;
	ctx->h[5] = 0x9b05688c2b3e6c1f;
	ctx->h[6] = 0x1f83d9abfb41bd6b;
	ctx->h[7] = 0x5be0cd19137e2179;
	
	ctx->length = 0;
}

void ampheck_sha512_transform(struct ampheck_sha512 *ctx, const uint8_t *data, size_t blocks)
{
	for (size_t i = 0; i < blocks; ++i)
	{
		uint64_t wv[8];
		uint64_t w[16];
		
		PACK_64_BE(&data[(i << 6)      ], &w[ 0]);
		PACK_64_BE(&data[(i << 6) +   8], &w[ 1]);
		PACK_64_BE(&data[(i << 6) +  16], &w[ 2]);
		PACK_64_BE(&data[(i << 6) +  24], &w[ 3]);
		PACK_64_BE(&data[(i << 6) +  32], &w[ 4]);
		PACK_64_BE(&data[(i << 6) +  40], &w[ 5]);
		PACK_64_BE(&data[(i << 6) +  48], &w[ 6]);
		PACK_64_BE(&data[(i << 6) +  56], &w[ 7]);
		PACK_64_BE(&data[(i << 6) +  64], &w[ 8]);
		PACK_64_BE(&data[(i << 6) +  72], &w[ 9]);
		PACK_64_BE(&data[(i << 6) +  80], &w[10]);
		PACK_64_BE(&data[(i << 6) +  88], &w[11]);
		PACK_64_BE(&data[(i << 6) +  96], &w[12]);
		PACK_64_BE(&data[(i << 6) + 104], &w[13]);
		PACK_64_BE(&data[(i << 6) + 112], &w[14]);
		PACK_64_BE(&data[(i << 6) + 120], &w[15]);
		
		wv[0] = ctx->h[0];
		wv[1] = ctx->h[1];
		wv[2] = ctx->h[2];
		wv[3] = ctx->h[3];
		wv[4] = ctx->h[4];
		wv[5] = ctx->h[5];
		wv[6] = ctx->h[6];
		wv[7] = ctx->h[7];
		
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, w[ 0], 0x428a2f98d728ae22);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, w[ 1], 0x7137449123ef65cd);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, w[ 2], 0xb5c0fbcfec4d3b2f);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, w[ 3], 0xe9b5dba58189dbbc);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, w[ 4], 0x3956c25bf348b538);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, w[ 5], 0x59f111f1b605d019);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, w[ 6], 0x923f82a4af194f9b);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, w[ 7], 0xab1c5ed5da6d8118);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, w[ 8], 0xd807aa98a3030242);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, w[ 9], 0x12835b0145706fbe);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, w[10], 0x243185be4ee4b28c);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, w[11], 0x550c7dc3d5ffb4e2);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, w[12], 0x72be5d74f27b896f);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, w[13], 0x80deb1fe3b1696b1);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, w[14], 0x9bdc06a725c71235);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, w[15], 0xc19bf174cf692694);
		
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 0), 0xe49b69c19ef14ad2);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 1), 0xefbe4786384f25e3);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT( 2), 0x0fc19dc68b8cd5b5);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT( 3), 0x240ca1cc77ac9c65);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT( 4), 0x2de92c6f592b0275);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT( 5), 0x4a7484aa6ea6e483);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT( 6), 0x5cb0a9dcbd41fbd4);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT( 7), 0x76f988da831153b5);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 8), 0x983e5152ee66dfab);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 9), 0xa831c66d2db43210);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT(10), 0xb00327c898fb213f);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT(11), 0xbf597fc7beef0ee4);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT(12), 0xc6e00bf33da88fc2);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT(13), 0xd5a79147930aa725);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT(14), 0x06ca6351e003826f);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT(15), 0x142929670a0e6e70);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 0), 0x27b70a8546d22ffc);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 1), 0x2e1b21385c26c926);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT( 2), 0x4d2c6dfc5ac42aed);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT( 3), 0x53380d139d95b3df);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT( 4), 0x650a73548baf63de);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT( 5), 0x766a0abb3c77b2a8);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT( 6), 0x81c2c92e47edaee6);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT( 7), 0x92722c851482353b);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 8), 0xa2bfe8a14cf10364);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 9), 0xa81a664bbc423001);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT(10), 0xc24b8b70d0f89791);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT(11), 0xc76c51a30654be30);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT(12), 0xd192e819d6ef5218);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT(13), 0xd69906245565a910);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT(14), 0xf40e35855771202a);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT(15), 0x106aa07032bbd1b8);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 0), 0x19a4c116b8d2d0c8);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 1), 0x1e376c085141ab53);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT( 2), 0x2748774cdf8eeb99);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT( 3), 0x34b0bcb5e19b48a8);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT( 4), 0x391c0cb3c5c95a63);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT( 5), 0x4ed8aa4ae3418acb);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT( 6), 0x5b9cca4f7763e373);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT( 7), 0x682e6ff3d6b2b8a3);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 8), 0x748f82ee5defb2fc);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 9), 0x78a5636f43172f60);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT(10), 0x84c87814a1f0ab72);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT(11), 0x8cc702081a6439ec);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT(12), 0x90befffa23631e28);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT(13), 0xa4506cebde82bde9);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT(14), 0xbef9a3f7b2c67915);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT(15), 0xc67178f2e372532b);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 0), 0xca273eceea26619c);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 1), 0xd186b8c721c0c207);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT( 2), 0xeada7dd6cde0eb1e);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT( 3), 0xf57d4f7fee6ed178);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT( 4), 0x06f067aa72176fba);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT( 5), 0x0a637dc5a2c898a6);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT( 6), 0x113f9804bef90dae);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT( 7), 0x1b710b35131c471b);
		SHA512_PRC(0, 1, 2, 3, 4, 5, 6, 7, SHA512_EXT( 8), 0x28db77f523047d84);
		SHA512_PRC(7, 0, 1, 2, 3, 4, 5, 6, SHA512_EXT( 9), 0x32caab7b40c72493);
		SHA512_PRC(6, 7, 0, 1, 2, 3, 4, 5, SHA512_EXT(10), 0x3c9ebe0a15c9bebc);
		SHA512_PRC(5, 6, 7, 0, 1, 2, 3, 4, SHA512_EXT(11), 0x431d67c49c100d4c);
		SHA512_PRC(4, 5, 6, 7, 0, 1, 2, 3, SHA512_EXT(12), 0x4cc5d4becb3e42b6);
		SHA512_PRC(3, 4, 5, 6, 7, 0, 1, 2, SHA512_EXT(13), 0x597f299cfc657e2a);
		SHA512_PRC(2, 3, 4, 5, 6, 7, 0, 1, SHA512_EXT(14), 0x5fcb6fab3ad6faec);
		SHA512_PRC(1, 2, 3, 4, 5, 6, 7, 0, SHA512_EXT(15), 0x6c44198c4a475817);
		
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

void ampheck_sha512_update(struct ampheck_sha512 *ctx, const uint8_t *data, size_t size)
{
	size_t tmp = size;
	
	if (size >= 128 - ctx->length % 128)
	{
		memcpy(&ctx->buffer[ctx->length % 128], data, 128 - ctx->length % 128);
		
		data += 128 - ctx->length % 128;
		size -= 128 - ctx->length % 128;
		
		ampheck_sha512_transform(ctx, ctx->buffer, 1);
		ampheck_sha512_transform(ctx, data, size / 128);
		
		data += size & ~127;
		size %= 128;
		
		memcpy(ctx->buffer, data, size);
	}
	else
	{
		memcpy(&ctx->buffer[ctx->length % 128], data, size);
	}
	
	ctx->length += tmp;
}

void ampheck_sha512_finish(const struct ampheck_sha512 *ctx, uint8_t *digest)
{
	struct ampheck_sha512 tmp;
	
	memcpy(tmp.h, ctx->h, 8 * sizeof(uint64_t));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 128);
	
	tmp.buffer[ctx->length % 128] = 0x80;
	
	if (ctx->length % 128 < 112)
	{
		memset(&tmp.buffer[ctx->length % 128 + 1], 0x00, 119 - ctx->length % 128);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 128 + 1], 0x00, 127 - ctx->length % 128);
		ampheck_sha512_transform(&tmp, tmp.buffer, 1);
		
		memset(tmp.buffer, 0x00, 120);
	}
	
	UNPACK_64_BE(ctx->length * 8, &tmp.buffer[120]);
	ampheck_sha512_transform(&tmp, tmp.buffer, 1);
	
	UNPACK_64_BE(tmp.h[0], &digest[ 0]);
	UNPACK_64_BE(tmp.h[1], &digest[ 8]);
	UNPACK_64_BE(tmp.h[2], &digest[16]);
	UNPACK_64_BE(tmp.h[3], &digest[24]);
	UNPACK_64_BE(tmp.h[4], &digest[32]);
	UNPACK_64_BE(tmp.h[5], &digest[40]);
	UNPACK_64_BE(tmp.h[6], &digest[48]);
	UNPACK_64_BE(tmp.h[7], &digest[56]);
}
