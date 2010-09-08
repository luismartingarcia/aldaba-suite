
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
/*                                                                            */
/*  Copyright (C) 2004-2007 Brad Conte.                                       */
/*                                                                            */
/* This SHA256 implementation is free software; you can redistribute it       */ 
/* and/or modify it under the terms of the GNU General Public License as      */
/* published by the Free Software Foundation; either version 2 of the         */
/* License, or any later version.                                             */
/*                                                                            */
/* It is distributed in the hope that it will be useful, but WITHOUT          */
/* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY         */
/* or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public           */
/* License for more details.                                                  */
/*                                                                            */
/* You should have received a copy of the GNU General Public License          */
/* along with Aldaba; if not, write to the Free Software Foundation,          */
/* Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA             */
/*                                                                            */
/******************************************************************************/
/*                                                                            */
/* Original documentation:                                                    */
/*                                                                            */
/*  - SHA256_CTX                                                              */
/*     A MD5 structure that will hold all hash-related data and calculations  */
/*     as the hash is calculated.                                             */
/*                                                                            */
/*  - SHA256_init(SHA256_CTX *ctx)                                            */
/*     Initializes the SHA256_CTX object.                                     */
/*                                                                            */
/*  - SHA1_update(SHA256_CTX *ctx, u8 data[], int len)                        */
/*     Once an object has been created and initialized, the data to be hashed */
/*     must be added. Due to practical limitations, it may not be optimal     */
/*     (or possible) to add all the data to the SHA256 hash in one data chunk,*/
/*     so the function inputs, stores, and calculates data as it is received, */
/*     allowing the data to be added in as many chunks as necessary.          */
/*                                                                            */
/*      -> u8 data[]                                                          */
/*              This is the data to be added to the hash.                     */
/*      -> int len                                                            */
/*              This is the length, in bytes, of the data in the "data" array.*/
/*                                                                            */
/*  - SHA256_final(SHA256_CTX *ctx, u8 hash[])                                */
/*     Finalize and output the hash.                                          */
/*                                                                            */
/*      -> u8 hash[]                                                          */
/*              This is the array to store the output hash. It must be at     */
/*              least 16 bytes in size.                                       */
/*                                                                            */
/* Code Usage:                                                                */
/*                                                                            */
/*    1. Create an SHA256_CTX object.                                         */
/*    2. Initialize it with sha256_init().                                    */
/*    3. Read some/all of the data to hash into an array, calculate the size  */
/*       of the data, and add it to the hash with sha256_update().            */
/*    4. Repeat the previous step for all the data you want to hash.          */
/*    5. Finalize and output the hash with sha256_final().                    */
/*                                                                            */
/* Repeat steps (2) to (5) for as many hashes as you want to calculate.       */
/*                                                                            */
/* Example:                                                                   */
/*                                                                            */
/* int main(){                                                                */
/*   u8 text1[]={"QWERTY"}, hash[32];                                         */
/*   SHA256_CTX ctx;                                                          */
/*                                                                            */
/*    sha256_init(&ctx);                                                      */
/*    sha256_update(&ctx,text1,strlen(text1));                                */ 
/*    sha256_final(&ctx,hash);                                                */
/*    sha256_printHash(hash);                                                 */
/*                                                                            */
/*    return 0;                                                               */
/* }                                                                          */
/*                                                                            */
/* Notes:                                                                     */
/* The 32-bit words (which in this case are unsigned integers) used in the    */
/* code use little endian byte ordering. The SHA-256 specification uses the   */
/* big endian byte order, so some byte-reversals are made when copying data   */ 
/* into and out of integers in this code.                                     */
/*                                                                            */
/* This algorithm can hash data of any length, although 264 bits              */
/* (2,147,483,648 gigabytes) is the recommended limit.                        */
/*                                                                            */
/* This algorithm has not actually been optimized. This algorithm has been    */
/* tested against numerous test vectors (including all official ones) and     */
/* has proven to be accurate.                                                 */
/*                                                                            */
/* Code originally published at: http://b-con.us/code/sha256_c.php. July 2006.*/
/*                                                                            */
/******************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)                  */
/*                                                                            */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)           */
/* $DESCRIPTION                                                               */
/*                                                                            */
/******************************************************************************/
/** \file sha256.c 
  * \brief SHA-256 hashing algorithm. */


#include "aldaba.h"
#include "sha256.h"



void SHA256::sha256_transform(SHA256_CTX *ctx, u8 data[]){

   u32 sha_k[64] = {
       0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
       0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
       0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
       0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
       0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
       0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
       0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
       0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

   static uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
      
   for (i=0,j=0; i < 16; ++i, j += 4)
      m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
   for ( ; i < 64; ++i)
      m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];
   
   for (i = 0; i < 64; ++i) {
      t1 = h + EP1(e) + CH(e,f,g) + sha_k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }
   
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
   
} /* End of sha256_transform() */  


void SHA256::sha256_init(SHA256_CTX *ctx){
    
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x6a09e667;
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;
    
} /* End of sha256_init() */


void SHA256::sha256_update(SHA256_CTX *ctx, const u8 data[], uint32_t len){
    
   uint32_t i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha256_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  /* End of sha256_update() */


void SHA256::sha256_final(SHA256_CTX *ctx, u8 hash[]){
    
   static uint32_t i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha256_transform(ctx,ctx->data);
      memset(ctx->data,0,56); 
   }  
   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],ctx->datalen * 8);
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha256_transform(ctx,ctx->data);
   
   // Since this implementation uses little endian byte ordering and SHA uses big endian,
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
      hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
      hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
      hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
   }  
   
}  /* End of sha256_final() */


/** Prints the hash hex values. @warning Supplied buffer must contain at least 
  * 32 bytes.                                                                 */
void SHA256::sha256_printHash(u8 hash[]){
    
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
   
} /* End of sha256_printHash() */


/** Generates a SHA-256 digest of the supplied buffer. The result is stored in 
  * buffer SHA256digest. @warning buffer SHA256digest must be able to hold at
  * least 32 bytes */
void SHA256::sha256sum(const u8 *buffer, unsigned len, u8 *SHA256digest){
 
 static SHA256_CTX ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, buffer, len);
  sha256_final(&ctx,SHA256digest);
 
} /* End of sha256sum() */

