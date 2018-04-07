
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <functional>
#include "hptools.h"

namespace {

/* ----------------------------------------------------------------------- */
/* ----------------------------------------------------------------------- */
/* - This MD5 implementation is a stripped-down version taken from       - */
/* - LibTomCrypt, which was released into public domain by Tom St Denis. - */
/* ----------------------------------------------------------------------- */
/* ----------------------------------------------------------------------- */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

struct md5_state {
    uint64_t length;
    uint32_t state[4], curlen;
    unsigned char buf[64];
};

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                       \
     { x = ((uint32_t)((y)[3] & 255)<<24) | \
           ((uint32_t)((y)[2] & 255)<<16) | \
           ((uint32_t)((y)[1] & 255)<<8)  | \
           ((uint32_t)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define ROL(x, y) \
     ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) \
     ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)

/**
  @file md5.c
  LTC_MD5 hash function by Tom St Denis 
 */

#define F(x,y,z)  (z ^ (x & (y ^ z)))
#define G(x,y,z)  (y ^ (z & (y ^ x)))
#define H(x,y,z)  (x^y^z)
#define I(x,y,z)  (y^(x|(~z)))

#ifdef LTC_SMALL_CODE

#define FF(a,b,c,d,M,s,t) \
    a = (a + F(b,c,d) + M + t); a = ROL(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
    a = (a + G(b,c,d) + M + t); a = ROL(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
    a = (a + H(b,c,d) + M + t); a = ROL(a, s) + b;

#define II(a,b,c,d,M,s,t) \
    a = (a + I(b,c,d) + M + t); a = ROL(a, s) + b;

static const unsigned char Worder[64] = {
   0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
   1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
   5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
   0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

static const unsigned char Rorder[64] = {
   7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
   5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
   4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
   6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const uint32_t Korder[64] = {
0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL, 0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL, 0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL, 0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL, 0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL, 0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL, 0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL, 0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL, 0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
};

#else

#define FF(a,b,c,d,M,s,t) \
    a = (a + F(b,c,d) + M + t); a = ROLc(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
    a = (a + G(b,c,d) + M + t); a = ROLc(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
    a = (a + H(b,c,d) + M + t); a = ROLc(a, s) + b;

#define II(a,b,c,d,M,s,t) \
    a = (a + I(b,c,d) + M + t); a = ROLc(a, s) + b;

#endif

static void md5_compress(md5_state *md, unsigned char *buf)
	{
    uint32_t i, W[16], a, b, c, d;
#ifdef LTC_SMALL_CODE
    uint32_t t;
#endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32L(W[i], buf + (4*i));
	}
 
    /* copy state */
    a = md->state[0];
    b = md->state[1];
    c = md->state[2];
    d = md->state[3];

#ifdef LTC_SMALL_CODE
    for (i = 0; i < 16; ++i) {
        FF(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
        t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 32; ++i) {
        GG(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
        t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 48; ++i) {
        HH(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
        t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 64; ++i) {
        II(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
        t = d; d = c; c = b; b = a; a = t;
    }

#else
    FF(a,b,c,d,W[0],7,0xd76aa478UL)
    FF(d,a,b,c,W[1],12,0xe8c7b756UL)
    FF(c,d,a,b,W[2],17,0x242070dbUL)
    FF(b,c,d,a,W[3],22,0xc1bdceeeUL)
    FF(a,b,c,d,W[4],7,0xf57c0fafUL)
    FF(d,a,b,c,W[5],12,0x4787c62aUL)
    FF(c,d,a,b,W[6],17,0xa8304613UL)
    FF(b,c,d,a,W[7],22,0xfd469501UL)
    FF(a,b,c,d,W[8],7,0x698098d8UL)
    FF(d,a,b,c,W[9],12,0x8b44f7afUL)
    FF(c,d,a,b,W[10],17,0xffff5bb1UL)
    FF(b,c,d,a,W[11],22,0x895cd7beUL)
    FF(a,b,c,d,W[12],7,0x6b901122UL)
    FF(d,a,b,c,W[13],12,0xfd987193UL)
    FF(c,d,a,b,W[14],17,0xa679438eUL)
    FF(b,c,d,a,W[15],22,0x49b40821UL)
    GG(a,b,c,d,W[1],5,0xf61e2562UL)
    GG(d,a,b,c,W[6],9,0xc040b340UL)
    GG(c,d,a,b,W[11],14,0x265e5a51UL)
    GG(b,c,d,a,W[0],20,0xe9b6c7aaUL)
    GG(a,b,c,d,W[5],5,0xd62f105dUL)
    GG(d,a,b,c,W[10],9,0x02441453UL)
    GG(c,d,a,b,W[15],14,0xd8a1e681UL)
    GG(b,c,d,a,W[4],20,0xe7d3fbc8UL)
    GG(a,b,c,d,W[9],5,0x21e1cde6UL)
    GG(d,a,b,c,W[14],9,0xc33707d6UL)
    GG(c,d,a,b,W[3],14,0xf4d50d87UL)
    GG(b,c,d,a,W[8],20,0x455a14edUL)
    GG(a,b,c,d,W[13],5,0xa9e3e905UL)
    GG(d,a,b,c,W[2],9,0xfcefa3f8UL)
    GG(c,d,a,b,W[7],14,0x676f02d9UL)
    GG(b,c,d,a,W[12],20,0x8d2a4c8aUL)
    HH(a,b,c,d,W[5],4,0xfffa3942UL)
    HH(d,a,b,c,W[8],11,0x8771f681UL)
    HH(c,d,a,b,W[11],16,0x6d9d6122UL)
    HH(b,c,d,a,W[14],23,0xfde5380cUL)
    HH(a,b,c,d,W[1],4,0xa4beea44UL)
    HH(d,a,b,c,W[4],11,0x4bdecfa9UL)
    HH(c,d,a,b,W[7],16,0xf6bb4b60UL)
    HH(b,c,d,a,W[10],23,0xbebfbc70UL)
    HH(a,b,c,d,W[13],4,0x289b7ec6UL)
    HH(d,a,b,c,W[0],11,0xeaa127faUL)
    HH(c,d,a,b,W[3],16,0xd4ef3085UL)
    HH(b,c,d,a,W[6],23,0x04881d05UL)
    HH(a,b,c,d,W[9],4,0xd9d4d039UL)
    HH(d,a,b,c,W[12],11,0xe6db99e5UL)
    HH(c,d,a,b,W[15],16,0x1fa27cf8UL)
    HH(b,c,d,a,W[2],23,0xc4ac5665UL)
    II(a,b,c,d,W[0],6,0xf4292244UL)
    II(d,a,b,c,W[7],10,0x432aff97UL)
    II(c,d,a,b,W[14],15,0xab9423a7UL)
    II(b,c,d,a,W[5],21,0xfc93a039UL)
    II(a,b,c,d,W[12],6,0x655b59c3UL)
    II(d,a,b,c,W[3],10,0x8f0ccc92UL)
    II(c,d,a,b,W[10],15,0xffeff47dUL)
    II(b,c,d,a,W[1],21,0x85845dd1UL)
    II(a,b,c,d,W[8],6,0x6fa87e4fUL)
    II(d,a,b,c,W[15],10,0xfe2ce6e0UL)
    II(c,d,a,b,W[6],15,0xa3014314UL)
    II(b,c,d,a,W[13],21,0x4e0811a1UL)
    II(a,b,c,d,W[4],6,0xf7537e82UL)
    II(d,a,b,c,W[11],10,0xbd3af235UL)
    II(c,d,a,b,W[2],15,0x2ad7d2bbUL)
    II(b,c,d,a,W[9],21,0xeb86d391UL)
#endif

    md->state[0] = md->state[0] + a;
    md->state[1] = md->state[1] + b;
    md->state[2] = md->state[2] + c;
    md->state[3] = md->state[3] + d;

#ifdef LTC_CLEAN_STACK
    memset(W, 0, sizeof(W));
    a = b = c = d = i = 0;
#ifdef LTC_SMALL_CODE
    t = 0;
#endif
#endif
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
void md5_init(md5_state * md)
{
    md->state[0] = 0x67452301UL;
    md->state[1] = 0xefcdab89UL;
    md->state[2] = 0x98badcfeUL;
    md->state[3] = 0x10325476UL;
    md->curlen = 0;
    md->length = 0;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
void md5_process(md5_state * md, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    while (inlen > 0) {
        if (md->curlen == 0 && inlen >= 64) {
            md5_compress(md, (unsigned char *)in);
            md->length += 64 * 8;
            in += 64;
            inlen -= 64;
        } else {
            n = (inlen < (64 - md->curlen)) ? inlen : (64 - md->curlen);
            memcpy(md->buf + md->curlen, in, (size_t)n);
            md->curlen += n;
            in += n;
            inlen -= n;
            if (md->curlen == 64) {
                md5_compress(md, md->buf);
                md->length += 64 * 8;
                md->curlen = 0;
            }
        }
    }
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (16 bytes)
*/
void md5_done(md5_state * md, unsigned char *out)
{
    int i;

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        md5_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(md->length, md->buf+56);
    md5_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 4; i++) {
        STORE32L(md->state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    memset(md, 0, sizeof(md5_state));
#endif
}

/**
  Self-test the hash
  @return true if successful
*/  
#ifdef LTC_TEST
bool md5_test(void)
{
  static const struct {
      char *msg;
      unsigned char hash[16];
  } tests[] = {
    { "",
      { 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e } },
    { "a",
      {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 
       0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 } },
    { "abc",
      { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 } },
    { "message digest", 
      { 0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0 } }, 
    { "abcdefghijklmnopqrstuvwxyz",
      { 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 
        0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b } },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      { 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 
        0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f } },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      { 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 
        0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a } }, 
    { NULL, { 0 } }
  };

  int i;
  unsigned char tmp[16];
  md5_state md;

  for (i = 0; tests[i].msg != NULL; i++) {
      md5_init(&md);
      md5_process(&md, (unsigned char *)tests[i].msg, (uint32_t)strlen(tests[i].msg));
      md5_done(&md, tmp);
      if (memcmp(tmp, tests[i].hash, 16) != 0) {
         return false;
}
  }
  return true;
}
#endif

/* ----------------------------------------------------------------------- */
/* ------ End of public domain MD5 implementation from LibTomCrypt. ------ */
/* ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* ----------------------------------------------------------------------- */
/* - This SHA256 implementation is a stripped-down version taken from    - */
/* - LibTomCrypt, which was released into public domain by Tom St Denis. - */
/* ----------------------------------------------------------------------- */
/* ----------------------------------------------------------------------- */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

struct sha256_state {
    uint64_t length;
    uint32_t state[8], curlen;
    unsigned char buf[64];
};

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define RORc(x, y) \
     ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)

/**
  @file sha256.c
  LTC_SHA256 by Tom St Denis 
*/

#ifdef LTC_SMALL_CODE
/* the K array */
static const uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
  };
#endif

/* Various logical functions */
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y)) 
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

/* compress 512-bits */
static void sha256_compress(sha256_state * md, unsigned char *buf)
    {
    uint32_t S[8], W[64], t0, t1;
#ifdef LTC_SMALL_CODE
    uint32_t t;
#endif
    int i;
    
    /* copy state into S */
    for (i = 0; i < 8; i++) {
        S[i] = md->state[i];
      }

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32H(W[i], buf + (4*i));
      }

    /* fill W[16..63] */
    for (i = 16; i < 64; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    /* Compress */
#ifdef LTC_SMALL_CODE   
#define RND(a,b,c,d,e,f,g,h,i)                         \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h  = t0 + t1;

     for (i = 0; i < 64; ++i) {
         RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
         t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; 
         S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
    }
#else 
#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
     t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                  \
     d += t0;                                        \
     h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

#undef RND     

#endif     

    /* feedback */
    for (i = 0; i < 8; i++) {
        md->state[i] = md->state[i] + S[i];
}

#ifdef LTC_CLEAN_STACK
    memset(S, 0, sizeof(S));
    memset(W, 0, sizeof(W));
    t0 = t1 = 0;
#ifdef LTC_SMALL_CODE
    t = 0;
#endif
#endif
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
void sha256_init(sha256_state * md)
{
    md->curlen = 0;
    md->length = 0;
    md->state[0] = 0x6A09E667UL;
    md->state[1] = 0xBB67AE85UL;
    md->state[2] = 0x3C6EF372UL;
    md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL;
    md->state[5] = 0x9B05688CUL;
    md->state[6] = 0x1F83D9ABUL;
    md->state[7] = 0x5BE0CD19UL;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
*/
void sha256_process(sha256_state * md, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    while (inlen > 0) {
        if (md->curlen == 0 && inlen >= 64) {
            sha256_compress(md, (unsigned char *)in);
            md->length += 64 * 8;
            in += 64;
            inlen -= 64;
        } else {
            n = (inlen < (64 - md->curlen)) ? inlen : (64 - md->curlen);
            memcpy(md->buf + md->curlen, in, (size_t)n);
            md->curlen += n;
            in += n;
            inlen -= n;
            if (md->curlen == 64) {
                sha256_compress(md, md->buf);
                md->length += 64 * 8;
                md->curlen = 0;
  }
}
  }
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
*/
void sha256_done(sha256_state * md, unsigned char *out)
{
    int i;

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        sha256_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->length, md->buf+56);
    sha256_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE32H(md->state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    memset(md, 0, sizeof(sha256_state));
#endif
}

/**
  Self-test the hash
  @return true if successful
*/  
#ifdef LTC_TEST
bool sha256_test(void)
{
  static const struct {
      char *msg;
      unsigned char hash[32];
  } tests[] = {
    { "abc",
      { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
    },
  };

  int i;
  unsigned char tmp[32];
  sha256_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
      sha256_init(&md);
      sha256_process(&md, (unsigned char*)tests[i].msg, (unsigned long)strlen(tests[i].msg));
      sha256_done(&md, tmp);
      if (memcmp(tmp, tests[i].hash, 32) != 0) {
         return false;
      }
}
  return true;
}
#endif

/* ----------------------------------------------------------------------- */
/* ---- End of public domain SHA256 implementation from LibTomCrypt. ----- */
/* ----------------------------------------------------------------------- */

} // namespace

void HomePlugTools::KeyFromPassword(
  const std::string& strPassword,
  unsigned char cKEY[8])
{
  std::string strSaltedPassword = strPassword + std::string("\x08\x85\x6D\xAF\x7C\xF5\x81\x85", 8);
  
  md5_state md5;
  unsigned char digest[16];
  md5_init(&md5);
  md5_process(&md5, (const unsigned char*)strSaltedPassword.data(), strSaltedPassword.size());
  md5_done(&md5, digest);

  for(int i = 2; i <= 1000; i++)
  {
    md5_init(&md5);
    md5_process(&md5, digest, 16);
    md5_done(&md5, digest);
  }

  memcpy(cKEY, digest, 8);

  for(int i = 0; i < 8; i++)
  {
    int iOneBits = 0;

    for(int j = 0x02; j != 0x00; j <<= 1)
      if(j & cKEY[i])
        iOneBits++;

    if((iOneBits & 0x01))
      cKEY[i] &= 0xFE;
    else
      cKEY[i] |= 0x01;
  }
}

void HomePlugAvTools::NetworkKeyFromPassword(
  const std::string& strPassword,
  unsigned char cKEY[16])
{
  std::string strSaltedSecret = strPassword.substr(0, 64) + std::string("\x08\x85\x6D\xAF\x7C\xF5\x81\x86", 8);
  
  sha256_state sha256;
  unsigned char digest[32];
  sha256_init(&sha256);
  sha256_process(&sha256, (const unsigned char*)strSaltedSecret.data(), strSaltedSecret.size());
  sha256_done(&sha256, digest);
  for(int i = 0; i < 999; i++) 
  {
    sha256_init(&sha256);
    sha256_process(&sha256, digest, 32);
    sha256_done(&sha256, digest);
  }
  
  memcpy(cKEY, digest, 16);
}

void HomePlugAvTools::DeviceAccessKeyFromSecurityID(
  const std::string& strSecurityID,
  unsigned char cDAK[16])
{
  std::string strSaltedSecret = strSecurityID.substr(0, 64) + std::string("\x08\x85\x6D\xAF\x7C\xF5\x81\x85", 8);
  
  sha256_state sha256;
  unsigned char digest[32];
  sha256_init(&sha256);
  sha256_process(&sha256, (const unsigned char*)strSaltedSecret.data(), strSaltedSecret.size());
  sha256_done(&sha256, digest);
  for(int i = 0; i < 999; i++) 
  {
    sha256_init(&sha256);
    sha256_process(&sha256, digest, 32);
    sha256_done(&sha256, digest);
  }
  
  memcpy(cDAK, digest, 16);
}

uint32_t HomePlugAvTools::Checksum(
  const uint32_t* pData, 
  size_t iWords)
{
  uint32_t ulCheckSum = 0;
  for(size_t i = 0; i < iWords; i++)
    ulCheckSum ^= pData[i];
  return ~ulCheckSum;
}
