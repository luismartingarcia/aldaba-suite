
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

/* This file is part of Aldaba Knocking Suite. Aldaba is licensed under   */
/* the GNU General Public License. However, the following code is public  */
/* domain. It can be used and distributed with no restrictions.           */
/*                                                                        */
/* Twofish Encryption Algorithm. (Bruce Schneier)                         */
/*                                                                        */
/* Implemented by Andrew Csillag.                                         */
/*   --> http://www.geocities.com/drew_csillag/                           */
/*                                                                        */
/* Modified by Luis Martin Garcia. December 5, 2007.                      */
/*   --> aldabaknocking [.at.] gmail.com                                  */
/*   --> http://www.aldabaknocking.com                                    */
/*                                                                        */
/* Original implementation available at:                                  */
/*   --> http://www.schneier.com/code/twofish-cpy.zip                     */
/*                                                                        */
/* Original Twofish paper:                                                */
/*   B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall, N. Ferguson  */
/*   Twofish: A 128-Bit Block Cipher. 15 June 1998.                       */ 
/*   http://www.schneier.com/paper-twofish-paper.html                     */
/*                                                                        */    
/**************************************************************************/
/* Original documentation:                                                */
/*                                                                        */    
/*                                                                        */    
/*    compiler is gcc(egcs-2.91.66)                                       */
/*    flags are -O3 -fomit-frame-pointer -Wall                            */
/*    Processor is 233Mhz Pentium II (Deschutes)                          */
/*    OS is Linux 2.2.16                                                  */
/*                                                                        */
/*    Max encryption speed I've seen (in mulit-user mode even, although   */
/*    single user mode probably won't save more than a couple clocks):    */
/*                                                                        */
/*    encs/sec = 506115.904591                                            */
/*    bytes/sec = 8097854.473457                                          */
/*    KB/sec = 7908.061009                                                */
/*    MB/sec = 7.722716                                                   */
/*    approx clocks/enc (for 233Mhz) = 461.027466                         */
/*                                                                        */
/*    I easily beat the best C implementations (the best being MSC @ 600  */
/*    clocks), so the target is the assembly implementations...           */
/*                                                                        */
/*    according to twofish docs, fully tuned *assembly* (in clocks):      */
/*    compiled is 285          (shouldn't be able to do this)(12.5 MB/sec)*/
/*    full keyed is 315        (if I get to 460, maybe this is possible   */
/*                              but I *really* doubt it)  (11.3 MB/sec)   */
/*    partially keyed is 460   (I'm *really* close) (7.7 MB/sec)          */
/*    minimal keying is 720    (I've beat this -their C did too)          */
/*                              (4.9 MB/sec)                              */
/*                                                                        */
/**************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)              */
/*                                                                        */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)       */
/* $DESCRIPTION                                                           */
/*                                                                        */
/**************************************************************************/
/** \file twofish.h 
  * \brief Twofish cipher. */


#include <stdint.h>

/* The original twofish code used the definition u32. It's better to link */
/* it to the standard  uint32_t defined in stdint.h                        */
typedef uint32_t u32;

#define BYTE unsigned char
#define RS_MOD 0x14D
#define RHO 0x01010101L


/* Prototypes */
void printSubkeys(u32 K[40]);
u32 polyMult(u32 a, u32 b);
u32 gfMod(u32 t, u32 modulus);
u32 RSMatrixMultiply(BYTE sd[8]);
u32 h(u32 X, u32 L[4], int k);
void fullKey(u32 L[4], int k, u32 QF[4][256]);
void printRound(int round, u32 R0, u32 R1, u32 R2, u32 R3, u32 K1, u32 K2);
inline void decrypt(u32 K[40], u32 S[4][256], BYTE CT[16], BYTE PT[16]);
inline void encrypt(u32 K[40], u32 S[4][256], BYTE CT[16], BYTE PT[16]);
void keySched(BYTE M[], int N, u32 **S, u32 K[40], int *k);
int twofish_decrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);
int twofish_encrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);
void twofish_printHex(BYTE b[], int lim);



/* gcc is smart enough to convert these to roll instructions.  If you want    */
/* to see for yourself, either do gcc -O3 -S, or change the |'s to +'s and    */
/* see how slow things get (you lose about 30-50 clocks) :).                  */
#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if BIG_ENDIAN == 1
    #define BSWAP(x) (((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF)))
#else
    #define BSWAP(x) (x)
#endif

#define _b(x, N) (((x) >> (N*8)) & 0xFF)

/* just casting to byte (instead of masking with 0xFF saves *tons* of clocks (around 50) */
#define b0(x) ((BYTE)(x))

/* this saved 10 clocks */
#define b1(x) ((BYTE)((x) >> 8))

/* use byte cast here saves around 10 clocks */
#define b2(x) (BYTE)((x) >> 16)

/* don't need to mask since all bits are in lower 8 - byte cast here saves    */
/* nothing, but hey, what the hell, it doesn't hurt any                       */
#define b3(x) (BYTE)((x) >> 24)  

#define BYTEARRAY_TO_U32(r) ((r[0] << 24) ^ (r[1] << 16) ^ (r[2] << 8) ^ r[3])
#define BYTES_TO_U32(r0, r1, r2, r3) ((r0 << 24) ^ (r1 << 16) ^ (r2 << 8) ^ r3)

#define u8 unsigned char



/* EOF */
