/*
This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include "WDS.h"

#define NTLMSSP_SIG_OFFSET					0x8
#define NTLMSSP_MSG_OFFSET					0x10
#define NTLMSSP_FLG_OFFSET					0x12


#define NTLMSSP_INITIAL						0
#define NTLMSSP_NEGOTIATE					1
#define NTLMSSP_CHALLENGE					2
#define NTLMSSP_AUTH						3
#define NTLMSSP_UNKNOWN						4
#define NTLMSSP_DONE						5
#define NTLMSSP_REQ_ENCRYPTED				16

#define NTLMSSP_NEGOTIATE_UNICODE			0x00000001
#define NTLMSSP_NEGOTIATE_OEM				0x00000002 /* x */
#define NTLMSSP_REQUEST_TARGET				0x00000004 /* x */
#define NTLMSSP_REQUEST_UNK1				0x00000008

#define NTLMSSP_NEGOTIATE_SIGN				0x00000010
#define NTLMSSP_NEGOTIATE_SEAL				0x00000020
#define NTLMSSP_NEGIOTATE_DGRAM				0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY			0x00000080

#define NTLMSSP_NEGOTIATE_NETWARE			0x00000100
#define NTLMSSP_NEGOTIATE_NTLM				0x00000200 /* x */
#define NTLMSSP_REQUEST_NT_ONLY				0x00000400
#define NTLMSSP_NEGIOTATE_ANONYMOUS			0x00000800

#define NTLMSSP_NEGOTIATE_DOMAIN			0x00001000
#define NTLMSSP_NEGOTIATE_WORKSTATION		0x00002000
#define NTLMSSP_NEGOTIATE_LOCALCALL			0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN		0x00008000 /* x */

#define NTLMSSP_TARGETTYPE_DOMAIN			0x00010000 /* x */
#define NTLMSSP_TARGETTYPE_SERVER			0x00020000
#define NTLMSSP_TARGETTYPE_SHARE			0x00040000
#define NTLMSSP_NEGOTIATE_EXTENDED_SEC		0x00080000

#define NTLMSSP_REQUEST_IDENTIFY			0x00100000
#define NTLMSSP_REQUEST_ACCEPT_RESP			0x00200000
#define NTLMSSP_REQUEST_NON_NT_SESSKEY		0x00400000
#define NTLMSSP_NEGOTIATE_TARGETINFO		0x00800000

#define NTLMSSP_REQUEST_UNK3				0x01000000
#define NTLMSSP_NEGIOTATE_VERSION			0x02000000
#define NTLMSSP_REQUEST_UNK5				0x04000000
#define NTLMSSP_REQUEST_UNK6				0x08000000

#define NTLMSSP_REQUEST_UNK7				0x10000000
#define NTLMSSP_NEGOTIATE_128				0x20000000
#define NTLMSSP_NEGOTIATE_KEYEXCH			0x40000000
#define NTLMSSP_NEGOTIATE_56				0x80000000

#define NTLMSSP_INFOTYPE_TERMINATOR			0x0000
#define NTLMSSP_INFOTYPE_SERVER				0x1
#define NTLMSSP_INFOTYPE_DOMAIN				0x2
#define NTLMSSP_INFOTYPE_DNS_HOSTNAME		0x3
#define NTLMSSP_INFOTYPE_DNS_DOMAIN			0x4
#define NTLMSSP_INFOTYPE_PARENT_DNSDOMAIN	0x5
#define NTLMSSP_INFOTYPE_FLAGS				0x6
#define NTLMSSP_INFOTYPE_TIMESTAMP			0x7
#define NTLMSSP_INFOTYPE_RESTRICTIONS		0x8
#define NTLMSSP_INFOTYPE_TARGETNAME			0x9
#define NTLMSSP_INFOTYPE_CHANNEL_BINDINGS	0xa

#define NTLMSSP_MESSAGE_HEADER				"NTLMSSP\0"

#define STATUS_SUCCESS						0x00000000
#define STATUS_INVALID_ACCOUNT_NAME			0xC0000062
#define STATUS_USER_EXISTS					0xC0000063
#define STATUS_NO_SUCH_USER					0xC0000064
#define STATUS_WRONG_PASSWORD				0xC000006a
#define STATUS_LOGON_FAILURE				/* 0xc000006d */ 0x8009030c
#define STATUS_INVALID_LOGON_HOURS			0xC000006F
#define STATUS_INVALID_WORKSTATION			0xC0000070
#define	STATUS_PASSWORD_EXPIRED				0xC0000071
#define STATUS_ACCOUNT_DISABLED				0xC0000072
#define STATUS_NOT_SUPPORTED				0xC00000BB
#define STATUS_NO_SUCH_DOMAIN				0xC00000DF
#define STATUS_INTERNAL_ERROR				0xC00000E5
#define STATUS_ACCOUNT_EXPIRED				0xC0000193
#define STATUS_PASSWORD_MUST_CHANGE			0xC0000224
#define STATUS_NOT_FOUND					0xC0000225
#define STATUS_ACCOUNT_LOCKED_OUT			0xC0000234
#define STATUS_INSUFFICIENT_LOGON_INFO		0xC0000250

typedef unsigned short int UINT2;
typedef unsigned long int UINT4;
typedef unsigned char *POINTER;

typedef struct MD5Context
{
	uint32_t buf[4];
	uint32_t bits[2];
	uint8_t in[64];
} MD5_CTX;

typedef struct MD4Context
{
	UINT4 state[4];
	UINT4 count[2];
	uint8_t buffer[64];
} MD4_CTX;

/* MD5 */
void MD5Init(MD5_CTX *ctx);
void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], MD5_CTX *ctx);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

/* MD4 */
void MD4Init(MD4_CTX *);
void MD4Update(MD4_CTX *, const unsigned char *, unsigned int);
void MD4Final(unsigned char[16], MD4_CTX *);

static void MD4Transform(UINT4[4], const unsigned char[64]);
static void _Encode(unsigned char *, UINT4 *, unsigned int);
static void _Decode(UINT4 *, const unsigned char *, unsigned int);

#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1
#define CLRBIT( STR, IDX) ((STR)[(IDX)/8] &= ~(0x01 << (7 - ((IDX)%8))))
#define SETBIT( STR, IDX) ((STR)[(IDX)/8] |= (0x01 << (7 - ((IDX)%8))))
#define GETBIT( STR, IDX) ((((STR)[(IDX)/8]) >> (7 - ((IDX)%8)) ) & 0x01)


#define MD5STEP(f, w, x, y, z, data, s) ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define FF(a, b, c, d, x, s) {(a) += F ((b), (c), (d)) + (x); (a) = ROTATE_LEFT ((a), (s));}
#define GG(a, b, c, d, x, s) {(a) += G ((b), (c), (d)) + (x) + (UINT4)0x5a827999; (a) = ROTATE_LEFT ((a), (s));}
#define HH(a, b, c, d, x, s) {(a) += H ((b), (c), (d)) + (x) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT ((a), (s));}
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

void generate_challenge(unsigned char* dest, const char* data);
void byteReverse(unsigned char *buf, unsigned longs);
void nt_response(uint8_t* dest, char* password, uint8_t* challenge);
void auth_DESkey8to7(unsigned char* dst, const unsigned char* key);
void auth_DEShash(unsigned char* dst, const unsigned char* key, const unsigned char* src);
void auth_LMresponse(uint8_t *dst, const uint8_t *hash, const uint8_t *challenge);
void auth_LMhash(uint8_t *dst, const uint8_t *pwd, const uint32_t pwdlen);