
/***************************************************************************
 *                                                                         *
 *                   _        _____               ____                     *
 *           /\     | |      |  __ \      /\     |  _ \      /\            *
 *          /  \    | |      | |  | |    /  \    | |_) |    /  \           *
 *         / /\ \   | |      | |  | |   / /\ \   |  _ <    / /\ \          *
 *        / ____ \  | |___   | |__| /  / ____ \  | |_) /  / ____ \         *
 *       /_/    \_\ | ____|  |_____/  /_/    \_\ |____/  /_/    \_\        *
 *                                                                         *
 *    == {Port Knocking/Single Packet Authorization} Security Suite ==     *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 * This file is part of Aldaba Knocking Suite.                             *
 *                                                                         *
 * Copyright (c) 2010, Luis MartinGarcia. (aldabaknocking@gmail.com)       *
 *                                                                         *
 * Aldaba is free software; you can redistribute it and/or modify it under *
 * the terms of the GNU General Public License as published by the Free    *
 * Software Foundation; Version 2 of the License, with the exceptions,     *
 * conditions and clarifications described in the file named LICENSE.txt,  *
 * distributed with Aldaba or available from:                              *
 * <http://www.aldabaknocking.com/LICENSE.txt>                             *
 *                                                                         *
 * Aldaba is distributed in the hope that it will be useful, but WITHOUT   *
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or   *
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License   *
 * v2.0 for more details.                                                  *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with Aldaba; if not, write to the Free Software Foundation, Inc.,       *
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA                *
 *                                                                         *
 * Please check file LICENSE.txt for the complete version of the license,  *
 * as this disclaimer does not contain the full information. Also, note    *
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/
/*                                                                        */
/* C implementation of the MD5 message-digest algorithm.                  */
/* Written by Colin Plumb in 1993.                                        */
/*                                                                        */
/* The code was slightly modified by Luis Martin Garcia to improve its    */
/* readability.                                                           */
/*                                                                        */
/* Aldaba is free software; you can redistribute it and/or modify         */
/* it under the terms of the GNU General Public License as published by   */
/* the Free Software Foundation; either version 2 of the License, or      */
/* any later version.                                                     */
/*                                                                        */
/* Aldaba is distributed in the hope that it will be useful, but WITHOUT  */
/* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY     */
/* or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public       */
/* License for more details.                                              */
/*                                                                        */
/* You should have received a copy of the GNU General Public License      */
/* along with Aldaba; if not, write to the Free Software Foundation,      */
/* Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA         */
/*                                                                        */
/**************************************************************************/
/* This code implements the MD5 message digest algorithm created by Ron   */
/* Rivest. It was written by Colin Plumb in 1993 and apparently there are */
/* no copyright restrictions to use it. I understand that this is public  */
/* domain and that the code can be used freely. If this is not correct    */
/* please write to aldabaknocking[.at.]gmail.com                          */
/*                                                                        */
/* There is another implementation from the RSA which is for sure free    */
/* to use but I've tested it and, interestingly, the results show that    */
/* Plumb's implementation is usually more than 30% faster. I guess the RSA*/
/* guys know a lot about cryptography but not that much about efficient   */
/* programming ;-)                                                        */
/*                                                                        */
/* Steps to compute the MD5 sum of a buffer:                              */
/* - Declare a structure of type MD5Context.                              */
/* - Initialise it calling md5_init()                                     */
/* - Call md5_update() passing the buffer you want to get the MD5 sum of. */
/* - Finally, call md5_final() passing a 16-byte array to get the digest. */
/*                                                                        */
/**************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)              */
/*                                                                        */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)       */
/* $DESCRIPTION                                                           */
/*                                                                        */
/* Sep 19, 2007. Developer: luismg (aldabaknocking [.at.] gmail.com)      */
/* -> Added function to simplify the MD5 calculation process:             */
/*    md5sum(unsigned char *buf, unsigned len, unsigned char *MD5digest)  */
/*    I think it's self explanatory.                                      */
/**************************************************************************/
/** \file md5.c 
  * \brief MD5 hashing algorithm. */


#include "aldaba.h"
#include "md5.h"



static int _ie = 0x44332211;

/** \brief Structure to test local endianness */
static union _mendian {
    uint32_t i;
    char b[4];
} *_endian = (union _mendian *)&_ie;


#define IS_BIG_ENDIAN()        (_endian->b[0] == '\x44')
#define IS_LITTLE_ENDIAN()     (_endian->b[0] == '\x11')



/** Reverse byte order. Note: this code is harmless on little-endian machines.*/
static void byteReverse(unsigned char *buf, unsigned longs){

 uint32 t=0;

  do {
    t = (uint32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
        ((unsigned) buf[1] << 8 | buf[0]);

    *(uint32 *) buf = t;
    buf += 4;

  } while (--longs);
}

/** Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
  * initialization constants.                                                 */
void md5_init(struct MD5Context *ctx, int brokenEndian)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;

    if ( IS_BIG_ENDIAN() ){

        if (brokenEndian)
            ctx->doByteReverse = 0;
        else 
            ctx->doByteReverse = 1;
    }
    else{
        ctx->doByteReverse = 0;
    }

} /* End of md5_init() */


/** Update context to reflect the concatenation of another buffer full of 
  *  bytes.                                                                   */
void md5_update(struct MD5Context *ctx, unsigned char const *buf, unsigned len){

 static uint32 t;
 unsigned char *p=NULL;
    
 t=0;

  /* Update bitcount */
  t = ctx->bits[0];
  if ( (ctx->bits[0] = t + ((uint32) len << 3)) < t )
    ctx->bits[1]++;        /* Carry from low to high */
  
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

  /* Handle any leading odd-sized chunks */
 
  if (t) {
    p = (unsigned char *) ctx->in + t;

    t = 64 - t;

    if (len < t) {
        memcpy(p, buf, len);
        return;
    }

    memcpy(p, buf, t);

    if (ctx->doByteReverse)
        byteReverse(ctx->in, 16);

    md5_transform(ctx->buf, (uint32 *) ctx->in);

    buf += t;
    len -= t;
  }
    
  /* Process data in 64-byte chunks */

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    if (ctx->doByteReverse)
        byteReverse(ctx->in, 16);

    md5_transform(ctx->buf, (uint32 *) ctx->in);

    buf += 64;
    len -= 64;
  }

  /* Handle any remaining bytes of data. */

  memcpy(ctx->in, buf, len);

}/* End of md5_update() */



/** Final wrap up - pad to 64-byte boundary with the bit pattern 1 0* (64-bit 
  * count of bits processed, MSB-first)                                       */
void md5_final(unsigned char digest[16], struct MD5Context *ctx){

 unsigned count=0;
 unsigned char *p=NULL;

  /* Compute number of bytes mod 64 */
  count = (ctx->bits[0] >> 3) & 0x3F;

  /* Set the first char of padding to 0x80. This is safe since there is */
  /* always at least one byte free                                      */
  p = ctx->in + count;
  *p++ = 0x80;

  /* Bytes of padding needed to make 64 bytes */
  count = 64 - 1 - count;

  /* Pad out to 56 mod 64 */
  if (count < 8) {
    /* Two lots of padding:  Pad the first block to 64 bytes */
    memset(p, 0, count);
    
    if (ctx->doByteReverse)
        byteReverse(ctx->in, 16);

    md5_transform(ctx->buf, (uint32 *) ctx->in);

    /* Now fill the next block with 56 bytes */
    memset(ctx->in, 0, 56);

  } else {
    /* Pad block to 56 bytes */
    memset(p, 0, count - 8);
  }

  if (ctx->doByteReverse)
    byteReverse(ctx->in, 14);

  /* Append length in bits and transform */
  ((uint32 *) ctx->in)[14] = ctx->bits[0];
  ((uint32 *) ctx->in)[15] = ctx->bits[1];

  md5_transform(ctx->buf, (uint32 *) ctx->in);
  
  if (ctx->doByteReverse)
    byteReverse((unsigned char *) ctx->buf, 4);

  memcpy(digest, ctx->buf, 16);
  memset(ctx, 0, sizeof(ctx));    /* In case it's sensitive */

} /* End of md5_final() */



/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )




/** The core of the MD5 algorithm, this alters an existing MD5 hash to reflect 
  * the addition of 16 longwords of new data.  md5_update blocks the data and 
  *  converts bytes into longwords for this routine.                          */
void md5_transform(uint32 buf[4], uint32 const in[16]){

 static uint32 a, b, c, d;

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

} /* End of md5_transform() */



/** Generates a MD5 digest of the supplied buffer. The result is stored in 
  * buffer MD5digest                                                          */
void md5sum(unsigned char *buffer, unsigned len, unsigned char *MD5digest){

 static MD5Context context;

  md5_init(&context,0);
  md5_update(&context, buffer, len);
  md5_final(MD5digest, &context);

} /* End of md5sum() */



/** Prints the hash hex values. 
  * @return value 0 on success and -1 in case of error.
  * @warning Supplied buffer must contain at least 16 bytes.                  */
int md5_printHash(unsigned char *MD5digest){

int i=0;

if( MD5digest == NULL )
    return -1;

 for (i=0; i<16; i++)
    printf("%02x", MD5digest[i]);

return 0;

} /* End of md5_printHash() */

