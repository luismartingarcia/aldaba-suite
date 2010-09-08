
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
/*      A MD5 structure that will hold all hash-related data and calculations */
/*      as the hash is calculated.                                            */
/*                                                                            */
/*  - SHA256_init(SHA256_CTX *ctx)                                            */
/*      Initializes the SHA256_CTX object.                                    */
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
/** \file sha256.h
  * \brief SHA-256 hashing algorithm. */

#ifndef __SHA256_H__
#define __SHA256_H__ 1

#include "aldaba.h"

#define SHA256_HASH_LEN 32


/** \brief SHA-256 context information */
typedef struct {
   u8 data[64];
   uint32_t datalen;
   uint32_t bitlen[2];
   uint32_t state[8];
} SHA256_CTX;


class SHA256 {

    private:

        /* DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it */
        #define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
        #define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
        #define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
        #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
        #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
        #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
        #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
        #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
        #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

    public:

        static void sha256_transform(SHA256_CTX *ctx, u8 data[]);
        static void sha256_init(SHA256_CTX *ctx);
        static void sha256_update(SHA256_CTX *ctx, const u8 data[], uint32_t len);
        static void sha256_final(SHA256_CTX *ctx, u8 hash[]);
        static void sha256_printHash(u8 hash[]);
        static void sha256sum(const u8 *buffer, unsigned len, u8 *SHA256digest);
    
}; /* End of class SHA256 */

#endif /* __SHA256_H__ */


