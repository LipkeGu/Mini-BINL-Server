/*
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

#include "WDS.h"

void byteReverse(unsigned char *buf, unsigned longs)
{
	uint32_t t = 0;
	do
	{
		t = (uint32_t)((unsigned)buf[3] << 8 | buf[2]) << 16 | ((unsigned)buf[1] << 8 | buf[0]);
		*(uint32_t *)buf = t;
		buf += 4;

	} while (--longs);
}

void MD5Init(MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;
	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len)
{
	uint32_t t;
	t = ctx->bits[0];

	if ((ctx->bits[0] = t + ((uint32_t)len << 3)) < t)
		ctx->bits[1]++;         /* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f;        /* Bytes already in shsInfo->data */

	if (t)
	{
		unsigned char *p = (unsigned char *)ctx->in + t;
		t = 64 - t;

		if (len < t)
		{
			memcpy(p, buf, len);
			return;
		}

		memcpy(p, buf, t);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *)ctx->in);
		buf += t;
		len -= t;
	}

	while (len >= 64)
	{
		memcpy(ctx->in, buf, 64);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *)ctx->in);
		buf += 64;
		len -= 64;
	}

	memcpy(ctx->in, buf, len);
}

void MD5Final(unsigned char digest[16], MD5_CTX *ctx)
{
	unsigned int count;
	unsigned char *p;

	count = (ctx->bits[0] >> 3) & 0x3F;
	p = ctx->in + count;
	*p++ = 0x80;

	count = 64 - 1 - count;

	if (count < 8)
	{

		memset(p, 0, count);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *)ctx->in);
		memset(ctx->in, 0, 56);
	}
	else
	{
		memset(p, 0, count - 8);
	}

	byteReverse(ctx->in, 14);
	((uint32_t *)ctx->in)[14] = ctx->bits[0];
	((uint32_t *)ctx->in)[15] = ctx->bits[1];

	MD5Transform(ctx->buf, (uint32_t *)ctx->in);
	byteReverse((unsigned char *)ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset((char *)ctx, 0, sizeof(ctx));       /* In case it's sensitive */
}

void MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

void generate_challenge(unsigned char* dest, const char* data)
{
	unsigned char digest[16] = "";
	struct MD5Context context;
	MD5Init(&context);
	MD5Update(&context, data, strlen(data));
	MD5Final(digest, &context);

	memcpy(dest, digest, 8);
}


void nt_response(uint8_t* dest, char* password, uint8_t* challenge)
{
	uint8_t hashedPW[16] = "";

	auth_LMhash(hashedPW, password, strlen(password));
	auth_LMresponse(dest, hashedPW, challenge);
}


unsigned int nt_buffer[16];
unsigned int output[4];
char hex_format[33];
char itoa16[16] = "0123456789abcdef";

static const uint8_t SMB_LMhash_Magic[8] =
{
	'K', 'G', 'S', '!', '@', '#', '$', '%'
};

void auth_LMhash(uint8_t *dst, const uint8_t *pwd, const uint32_t pwdlen)
{
	uint32_t max14 = 0, i;

	uint8_t tmp_pwd[14] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	max14 = pwdlen > 14 ? 14 : pwdlen;

	for (i = 0; i < max14; i++)
		tmp_pwd[i] = pwd[i];

	auth_DEShash(dst, tmp_pwd, SMB_LMhash_Magic);
	auth_DEShash(&dst[8], &tmp_pwd[7], SMB_LMhash_Magic);
}

void auth_LMresponse(uint8_t *dst, const uint8_t *hash, const uint8_t *challenge)
{
	unsigned char tmp[7] = { hash[14], hash[15], 0, 0, 0, 0, 0 }; /* 3rd key is nul-padded. */

	auth_DEShash(dst, hash, challenge);
	auth_DEShash(&dst[8], &hash[7], challenge);
	auth_DEShash(&dst[16], tmp, challenge);
}

static const uint8_t InitialPermuteMap[64] =
{
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6
};

static const uint8_t KeyPermuteMap[56] =
{
	49, 42, 35, 28, 21, 14, 7, 0, 50, 43, 36, 29, 22, 15, 8, 1,
	51, 44, 37, 30, 23, 16, 9, 2, 52, 45, 38, 31, 55, 48, 41, 34,
	27, 20, 13, 6, 54, 47, 40, 33, 26, 19, 12, 5, 53, 46, 39, 32,
	25, 18, 11, 4, 24, 17, 10, 3
};

static const uint8_t KeyRotation[16] =
{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t KeyCompression[48] =
{
	13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
	25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

static const uint8_t DataExpansion[48] =
{
	31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
	11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
	21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0
};

static const uint8_t SBox[8][64] =
{
	{   /* S0 */
		14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
		3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
		4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
		15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13
	},
	{   /* S1 */
		15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
		9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
		0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
		5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
	},
	{   /* S2 */
		10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
		1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
		13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
		11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12
	},
	{   /* S3 */
		7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
		1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
		10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
		15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14
	},
	{   /* S4 */
		2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
		8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
		4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
		15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3
	},
	{   /* S5 */
		12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
		0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
		9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
		7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13
	},
	{   /* S6 */
		4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
		3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
		1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
		10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12
	},
	{   /* S7 */
		13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
		10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
		7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
		0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
	}
};

static const uint8_t PBox[32] =
{
	15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
	1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24
};

static const uint8_t FinalPermuteMap[64] =
{
	7, 39, 15, 47, 23, 55, 31, 63, 6, 38, 14, 46, 22, 54, 30, 62,
	5, 37, 13, 45, 21, 53, 29, 61, 4, 36, 12, 44, 20, 52, 28, 60,
	3, 35, 11, 43, 19, 51, 27, 59, 2, 34, 10, 42, 18, 50, 26, 58,
	1, 33, 9, 41, 17, 49, 25, 57, 0, 32, 8, 40, 16, 48, 24, 56
};

static void Permute(unsigned char *dst, const unsigned char *src, const uint8_t *map, const int mapsize)
{
	int bitcount = 0;
	int i = 0;

	for (i = 0; i < mapsize; i++)
		dst[i] = 0;

	bitcount = mapsize * 8;

	for (i = 0; i < bitcount; i++)
	{
		if (GETBIT(src, map[i]))
			SETBIT(dst, i);
	}
}

static void KeyShift(unsigned char *key, const int numbits)
{
	int  i;
	unsigned char keep = key[0];

	for (i = 0; i < numbits; i++)
	{
		int j;

		for (j = 0; j < 7; j++)
		{
			if (j && (key[j] & 0x80))
				key[j - 1] |= 0x01;

			key[j] <<= 1;
		}

		if (GETBIT(key, 27))
		{
			CLRBIT(key, 27);
			SETBIT(key, 55);
		}

		if (keep & 0x80)
			SETBIT(key, 27);

		keep <<= 1;
	}
}

static void sbox(unsigned char *dst, const unsigned char *src)
{
	int i;

	for (i = 0; i < 4; i++)
		dst[i] = 0;

	for (i = 0; i < 8; i++)
	{
		int j;
		int Snum;
		int bitnum;

		for (Snum = j = 0, bitnum = (i * 6); j < 6; j++, bitnum++)
		{
			Snum <<= 1;
			Snum |= GETBIT(src, bitnum);
		}

		if (0 == (i % 2))
			dst[i / 2] |= ((SBox[i][Snum]) << 4);
		else
			dst[i / 2] |= SBox[i][Snum];
	}
}

static void xor(unsigned char *dst, const unsigned char *a, const unsigned char *b, const int count)
{
	int i;

	for (i = 0; i < count; i++)
		dst[i] = a[i] ^ b[i];
}

void auth_DESkey8to7(unsigned char *dst, const unsigned char *key)
{
	int i;
	unsigned char tmp[7];

	static const uint8_t map8to7[56] =
	{
		0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14,
		16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30,
		32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46,
		48, 49, 50, 51, 52, 53, 54, 56, 57, 58, 59, 60, 61, 62
	};

	Permute(tmp, key, map8to7, 7);

	for (i = 0; i < 7; i++)
		dst[i] = tmp[i];
}

void auth_DEShash(unsigned char *dst, const unsigned char *key, const unsigned char *src)
{
	int  i;
	unsigned char K[7];
	unsigned char D[8];

	Permute(K, key, KeyPermuteMap, 7);
	Permute(D, src, InitialPermuteMap, 8);

	for (i = 0; i < 16; i++)
	{
		int  j;
		unsigned char *L = D;
		unsigned char *R = &(D[4]);
		unsigned char Rexp[6];
		unsigned char Rn[4];
		unsigned char SubK[6];

		KeyShift(K, KeyRotation[i]);
		Permute(SubK, K, KeyCompression, 6);

		Permute(Rexp, R, DataExpansion, 6);
		xor (Rexp, Rexp, SubK, 6);

		sbox(Rn, Rexp);
		Permute(Rexp, Rn, PBox, 4);
		xor (Rn, L, Rexp, 4);

		for (j = 0; j < 4; j++)
		{
			L[j] = R[j];
			R[j] = Rn[j];
		}
	}

	Permute(dst, D, FinalPermuteMap, 8);
}

static unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void MD4Init(MD4_CTX *context)
{
	context->count[0] = context->count[1] = 0;

	/* Load magic initialization constants.*/
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

void MD4Update(MD4_CTX *context, const unsigned char *input, unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
		context->count[1]++;

	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.*/
	if (inputLen >= partLen)
	{
		memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MD4Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD4Transform(context->state, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen - i);
}

void MD4Final(unsigned char digest[16], MD4_CTX *context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	_Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.*/
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD4Update(context, PADDING, padLen);

	/* Append length (before padding) */
	MD4Update(context, bits, 8);

	/* Store state in digest */
	_Encode(digest, context->state, 16);

	/* Zeroize sensitive information.*/
	memset((POINTER)context, 0, sizeof(*context));
}

static void MD4Transform(UINT4 state[4], const unsigned char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	_Decode(x, block, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11); 				/* 1 */
	FF(d, a, b, c, x[1], S12); 				/* 2 */
	FF(c, d, a, b, x[2], S13); 				/* 3 */
	FF(b, c, d, a, x[3], S14); 				/* 4 */
	FF(a, b, c, d, x[4], S11); 				/* 5 */
	FF(d, a, b, c, x[5], S12); 				/* 6 */
	FF(c, d, a, b, x[6], S13); 				/* 7 */
	FF(b, c, d, a, x[7], S14); 				/* 8 */
	FF(a, b, c, d, x[8], S11); 				/* 9 */
	FF(d, a, b, c, x[9], S12); 				/* 10 */
	FF(c, d, a, b, x[10], S13); 			/* 11 */
	FF(b, c, d, a, x[11], S14); 			/* 12 */
	FF(a, b, c, d, x[12], S11); 			/* 13 */
	FF(d, a, b, c, x[13], S12); 			/* 14 */
	FF(c, d, a, b, x[14], S13); 			/* 15 */
	FF(b, c, d, a, x[15], S14); 			/* 16 */

											/* Round 2 */
	GG(a, b, c, d, x[0], S21); 			/* 17 */
	GG(d, a, b, c, x[4], S22); 			/* 18 */
	GG(c, d, a, b, x[8], S23); 			/* 19 */
	GG(b, c, d, a, x[12], S24); 			/* 20 */
	GG(a, b, c, d, x[1], S21); 			/* 21 */
	GG(d, a, b, c, x[5], S22); 			/* 22 */
	GG(c, d, a, b, x[9], S23); 			/* 23 */
	GG(b, c, d, a, x[13], S24); 			/* 24 */
	GG(a, b, c, d, x[2], S21); 			/* 25 */
	GG(d, a, b, c, x[6], S22); 			/* 26 */
	GG(c, d, a, b, x[10], S23); 			/* 27 */
	GG(b, c, d, a, x[14], S24); 			/* 28 */
	GG(a, b, c, d, x[3], S21); 			/* 29 */
	GG(d, a, b, c, x[7], S22); 			/* 30 */
	GG(c, d, a, b, x[11], S23); 			/* 31 */
	GG(b, c, d, a, x[15], S24); 			/* 32 */

											/* Round 3 */
	HH(a, b, c, d, x[0], S31);				/* 33 */
	HH(d, a, b, c, x[8], S32); 			/* 34 */
	HH(c, d, a, b, x[4], S33); 			/* 35 */
	HH(b, c, d, a, x[12], S34); 			/* 36 */
	HH(a, b, c, d, x[2], S31); 			/* 37 */
	HH(d, a, b, c, x[10], S32); 			/* 38 */
	HH(c, d, a, b, x[6], S33); 			/* 39 */
	HH(b, c, d, a, x[14], S34); 			/* 40 */
	HH(a, b, c, d, x[1], S31); 			/* 41 */
	HH(d, a, b, c, x[9], S32); 			/* 42 */
	HH(c, d, a, b, x[5], S33); 			/* 43 */
	HH(b, c, d, a, x[13], S34); 			/* 44 */
	HH(a, b, c, d, x[3], S31); 			/* 45 */
	HH(d, a, b, c, x[11], S32); 			/* 46 */
	HH(c, d, a, b, x[7], S33); 			/* 47 */
	HH(b, c, d, a, x[15], S34);			/* 48 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information.*/
	memset((POINTER)x, 0, sizeof(x));
}

static void _Encode(unsigned char *out, UINT4 *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		out[j] = (unsigned char)(input[i] & 0xff);
		out[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		out[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		out[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}


/* Decodes input (unsigned char) into output (UINT4). Assumes len is a multiple of 4. */
static void _Decode(UINT4 *out, const unsigned char *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		out[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) | (((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
}