
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
/** \file twofish.c 
  * \brief Twofish cipher. */


#include "aldaba.h"
#include "twofish.h"


u8 RS[4][8] = {
    { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, },
    { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5, },
    { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19, },
    { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03, },
};



u8 Q0[] = {
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0, 
};



u8 Q1[] = {
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91, 
};



u8 mult5B[] = {
    0x00, 0x5B, 0xB6, 0xED, 0x05, 0x5E, 0xB3, 0xE8, 
    0x0A, 0x51, 0xBC, 0xE7, 0x0F, 0x54, 0xB9, 0xE2, 
    0x14, 0x4F, 0xA2, 0xF9, 0x11, 0x4A, 0xA7, 0xFC, 
    0x1E, 0x45, 0xA8, 0xF3, 0x1B, 0x40, 0xAD, 0xF6, 
    0x28, 0x73, 0x9E, 0xC5, 0x2D, 0x76, 0x9B, 0xC0, 
    0x22, 0x79, 0x94, 0xCF, 0x27, 0x7C, 0x91, 0xCA, 
    0x3C, 0x67, 0x8A, 0xD1, 0x39, 0x62, 0x8F, 0xD4, 
    0x36, 0x6D, 0x80, 0xDB, 0x33, 0x68, 0x85, 0xDE, 
    0x50, 0x0B, 0xE6, 0xBD, 0x55, 0x0E, 0xE3, 0xB8, 
    0x5A, 0x01, 0xEC, 0xB7, 0x5F, 0x04, 0xE9, 0xB2, 
    0x44, 0x1F, 0xF2, 0xA9, 0x41, 0x1A, 0xF7, 0xAC, 
    0x4E, 0x15, 0xF8, 0xA3, 0x4B, 0x10, 0xFD, 0xA6, 
    0x78, 0x23, 0xCE, 0x95, 0x7D, 0x26, 0xCB, 0x90, 
    0x72, 0x29, 0xC4, 0x9F, 0x77, 0x2C, 0xC1, 0x9A, 
    0x6C, 0x37, 0xDA, 0x81, 0x69, 0x32, 0xDF, 0x84, 
    0x66, 0x3D, 0xD0, 0x8B, 0x63, 0x38, 0xD5, 0x8E, 
    0xA0, 0xFB, 0x16, 0x4D, 0xA5, 0xFE, 0x13, 0x48, 
    0xAA, 0xF1, 0x1C, 0x47, 0xAF, 0xF4, 0x19, 0x42, 
    0xB4, 0xEF, 0x02, 0x59, 0xB1, 0xEA, 0x07, 0x5C, 
    0xBE, 0xE5, 0x08, 0x53, 0xBB, 0xE0, 0x0D, 0x56, 
    0x88, 0xD3, 0x3E, 0x65, 0x8D, 0xD6, 0x3B, 0x60, 
    0x82, 0xD9, 0x34, 0x6F, 0x87, 0xDC, 0x31, 0x6A, 
    0x9C, 0xC7, 0x2A, 0x71, 0x99, 0xC2, 0x2F, 0x74, 
    0x96, 0xCD, 0x20, 0x7B, 0x93, 0xC8, 0x25, 0x7E, 
    0xF0, 0xAB, 0x46, 0x1D, 0xF5, 0xAE, 0x43, 0x18, 
    0xFA, 0xA1, 0x4C, 0x17, 0xFF, 0xA4, 0x49, 0x12, 
    0xE4, 0xBF, 0x52, 0x09, 0xE1, 0xBA, 0x57, 0x0C, 
    0xEE, 0xB5, 0x58, 0x03, 0xEB, 0xB0, 0x5D, 0x06, 
    0xD8, 0x83, 0x6E, 0x35, 0xDD, 0x86, 0x6B, 0x30, 
    0xD2, 0x89, 0x64, 0x3F, 0xD7, 0x8C, 0x61, 0x3A, 
    0xCC, 0x97, 0x7A, 0x21, 0xC9, 0x92, 0x7F, 0x24, 
    0xC6, 0x9D, 0x70, 0x2B, 0xC3, 0x98, 0x75, 0x2E, 
};



u8 multEF[] = {
    0x00, 0xEF, 0xB7, 0x58, 0x07, 0xE8, 0xB0, 0x5F, 
    0x0E, 0xE1, 0xB9, 0x56, 0x09, 0xE6, 0xBE, 0x51, 
    0x1C, 0xF3, 0xAB, 0x44, 0x1B, 0xF4, 0xAC, 0x43, 
    0x12, 0xFD, 0xA5, 0x4A, 0x15, 0xFA, 0xA2, 0x4D, 
    0x38, 0xD7, 0x8F, 0x60, 0x3F, 0xD0, 0x88, 0x67, 
    0x36, 0xD9, 0x81, 0x6E, 0x31, 0xDE, 0x86, 0x69, 
    0x24, 0xCB, 0x93, 0x7C, 0x23, 0xCC, 0x94, 0x7B, 
    0x2A, 0xC5, 0x9D, 0x72, 0x2D, 0xC2, 0x9A, 0x75, 
    0x70, 0x9F, 0xC7, 0x28, 0x77, 0x98, 0xC0, 0x2F, 
    0x7E, 0x91, 0xC9, 0x26, 0x79, 0x96, 0xCE, 0x21, 
    0x6C, 0x83, 0xDB, 0x34, 0x6B, 0x84, 0xDC, 0x33, 
    0x62, 0x8D, 0xD5, 0x3A, 0x65, 0x8A, 0xD2, 0x3D, 
    0x48, 0xA7, 0xFF, 0x10, 0x4F, 0xA0, 0xF8, 0x17, 
    0x46, 0xA9, 0xF1, 0x1E, 0x41, 0xAE, 0xF6, 0x19, 
    0x54, 0xBB, 0xE3, 0x0C, 0x53, 0xBC, 0xE4, 0x0B, 
    0x5A, 0xB5, 0xED, 0x02, 0x5D, 0xB2, 0xEA, 0x05, 
    0xE0, 0x0F, 0x57, 0xB8, 0xE7, 0x08, 0x50, 0xBF, 
    0xEE, 0x01, 0x59, 0xB6, 0xE9, 0x06, 0x5E, 0xB1, 
    0xFC, 0x13, 0x4B, 0xA4, 0xFB, 0x14, 0x4C, 0xA3, 
    0xF2, 0x1D, 0x45, 0xAA, 0xF5, 0x1A, 0x42, 0xAD, 
    0xD8, 0x37, 0x6F, 0x80, 0xDF, 0x30, 0x68, 0x87, 
    0xD6, 0x39, 0x61, 0x8E, 0xD1, 0x3E, 0x66, 0x89, 
    0xC4, 0x2B, 0x73, 0x9C, 0xC3, 0x2C, 0x74, 0x9B, 
    0xCA, 0x25, 0x7D, 0x92, 0xCD, 0x22, 0x7A, 0x95, 
    0x90, 0x7F, 0x27, 0xC8, 0x97, 0x78, 0x20, 0xCF, 
    0x9E, 0x71, 0x29, 0xC6, 0x99, 0x76, 0x2E, 0xC1, 
    0x8C, 0x63, 0x3B, 0xD4, 0x8B, 0x64, 0x3C, 0xD3, 
    0x82, 0x6D, 0x35, 0xDA, 0x85, 0x6A, 0x32, 0xDD, 
    0xA8, 0x47, 0x1F, 0xF0, 0xAF, 0x40, 0x18, 0xF7, 
    0xA6, 0x49, 0x11, 0xFE, 0xA1, 0x4E, 0x16, 0xF9, 
    0xB4, 0x5B, 0x03, 0xEC, 0xB3, 0x5C, 0x04, 0xEB, 
    0xBA, 0x55, 0x0D, 0xE2, 0xBD, 0x52, 0x0A, 0xE5, 
};










void printSubkeys(u32 K[40])
{
    int i;
    printf("round subkeys\n");
    for (i=0;i<40;i+=2)
	    printf("%08X %08X\n", K[i], K[i+1]);

} /* End of printSubkeys() */










/** Multiply two polynomials represented as u32's, actually called with BYTES,
  * but since I'm not really going to too much work to optimize key setup 
  * (since raw encryption speed is what I'm after), big deal.                 */
u32 polyMult(u32 a, u32 b){

 static u32 t;
    
 t=0;
 
  while(a){

    /*printf("A=%X  B=%X  T=%X\n", a, b, t);*/
	if (a&1) 
        t^=b;

	b <<= 1;
	a >>= 1;
  }
 
  return t;

} /* End of polyMult() */










    
/** take the polynomial t and return the t % modulus in GF(256).              */
u32 gfMod(u32 t, u32 modulus){

 int i;
 static u32 tt;

  modulus <<= 7;
  for (i = 0; i < 8; i++){
    tt = t ^ modulus;

	if (tt < t) 
        t = tt;

    modulus >>= 1;
  }

  return t;

} /* End of gfMod() */










/** multiply a and b and return the modulus                                   */
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)

/** return a u32 containing the result of multiplying the RS Code matrix by the 
  * sd matrix.                                                                */
u32 RSMatrixMultiply(BYTE sd[8]){

 int j, k;
 static BYTE t;
 static BYTE result[4];

  for (j = 0; j < 4; j++){
	t = 0;

	for (k = 0; k < 8; k++){
	    /*printf("t=%X  %X\n", t, gfMult(RS[j][k], sd[k], RS_MOD));*/
	    t ^= gfMult(RS[j][k], sd[k], RS_MOD);
	}

    result[3-j] = t;
  }

  return BYTEARRAY_TO_U32(result);

} /* End of RSMatrixMultiply() */










/** the Zero-keyed h function (used by the key setup routine)                 */
u32 h(u32 X, u32 L[4], int k){
    
 static BYTE y0, y1, y2, y3;
 static BYTE z0, z1, z2, z3;
 y0 = b0(X);
 y1 = b1(X);
 y2 = b2(X);
 y3 = b3(X);

    switch(k){
        
	case 4:
	    y0 = Q1[y0] ^ b0(L[3]);
	    y1 = Q0[y1] ^ b1(L[3]);
	    y2 = Q0[y2] ^ b2(L[3]);
	    y3 = Q1[y3] ^ b3(L[3]);
	case 3:
	    y0 = Q1[y0] ^ b0(L[2]);
	    y1 = Q1[y1] ^ b1(L[2]);
	    y2 = Q0[y2] ^ b2(L[2]);
	    y3 = Q0[y3] ^ b3(L[2]);
	case 2:
	    y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
	    y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
	    y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
	    y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    }

    /* inline the MDS matrix multiply */
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3]; 
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3]; 
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3; 
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3]; 

    return BYTES_TO_U32(z0, z1, z2, z3);
    
} /* End of h() */











/** given the Sbox keys, create the fully keyed QF.                           */
void fullKey(u32 L[4], int k, u32 QF[4][256]){
    
 static BYTE y0, y1, y2, y3;
 int i;
    
    /* for all input values to the Q permutations */
    for (i=0; i<256; i++)
    {
	    /* run the Q permutations */
	    y0 = i; y1=i; y2=i; y3=i;
	    switch(k){
            
    	    case 4:
    		y0 = Q1[y0] ^ b0(L[3]);
    		y1 = Q0[y1] ^ b1(L[3]);
    		y2 = Q0[y2] ^ b2(L[3]);
    		y3 = Q1[y3] ^ b3(L[3]);
    	    case 3:
    		y0 = Q1[y0] ^ b0(L[2]);
    		y1 = Q1[y1] ^ b1(L[2]);
    		y2 = Q0[y2] ^ b2(L[2]);
    		y3 = Q0[y3] ^ b3(L[2]);
    	    case 2:
    		y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
    		y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
    		y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
    		y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
	    }
	
	/* now do the partial MDS matrix multiplies */
        QF[0][i] = ((multEF[y0] << 24) 
                | (multEF[y0] << 16) 
                | (mult5B[y0] << 8)
                | y0);
        QF[1][i] = ((y1 << 24) 
                | (mult5B[y1] << 16) 
                | (multEF[y1] << 8)
                | multEF[y1]);
        QF[2][i] = ((multEF[y2] << 24) 
                | (y2 << 16) 
                | (multEF[y2] << 8)
                | mult5B[y2]);
        QF[3][i] = ((mult5B[y3] << 24) 
                | (multEF[y3] << 16)
                | (y3 << 8) 
                | mult5B[y3]);
    }
    
} /* End of fullKey() */











//void printRound(int round, u32 R0, u32 R1, u32 R2, u32 R3, u32 UNUSED(K1), u32 UNUSED(K2))
//{
    //printf("round[%d] ['0x%08XL', '0x%08XL', '0x%08XL', '0x%08XL']\n", 
	   //round, R0, R1, R2, R3);

//} /* End of printRound() */











/** fully keyed h (aka g) function.                                           */
#define fkh(X) (S[0][b0(X)]^S[1][b1(X)]^S[2][b2(X)]^S[3][b3(X)])

/* one encryption round */
#define ENC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROR(R2 ^ (T1 + T0 + K[2*round+8]), 1); \
    R3 = ROL(R3, 1) ^ (2*T1 + T0 + K[2*round+9]); 

/* one decryption round */
#define DEC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROL(R2, 1) ^ (T0 + T1 + K[2*round+8]); \
    R3 = ROR(R3 ^ (T0 + 2*T1 + K[2*round+9]), 1); 
    
    
    
    
    
    
    
    
    
    
/** Decrypt one block.                                                        */
inline void decrypt(u32 K[40], u32 S[4][256], BYTE CT[16], BYTE PT[16]){
    
 static u32 T0, T1;
 static u32 R0, R1, R2, R3;

    /* load/byteswap/whiten input */
    R3 = K[7] ^ BSWAP(((u32*)CT)[3]);
    R2 = K[6] ^ BSWAP(((u32*)CT)[2]);
    R1 = K[5] ^ BSWAP(((u32*)CT)[1]);
    R0 = K[4] ^ BSWAP(((u32*)CT)[0]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3, 9);
    DEC_ROUND(R2, R3, R0, R1, 8);
    DEC_ROUND(R0, R1, R2, R3, 7);
    DEC_ROUND(R2, R3, R0, R1, 6);
    DEC_ROUND(R0, R1, R2, R3, 5);
    DEC_ROUND(R2, R3, R0, R1, 4);
    DEC_ROUND(R0, R1, R2, R3, 3);
    DEC_ROUND(R2, R3, R0, R1, 2);
    DEC_ROUND(R0, R1, R2, R3, 1);
    DEC_ROUND(R2, R3, R0, R1, 0);

    /* load/byteswap/whiten output */
    ((u32*)PT)[3] = BSWAP(R1 ^ K[3]);
    ((u32*)PT)[2] = BSWAP(R0 ^ K[2]);
    ((u32*)PT)[1] = BSWAP(R3 ^ K[1]);
    ((u32*)PT)[0] = BSWAP(R2 ^ K[0]);

} /* End of decrypt() */









/** Encrypt one block.                                                        */
inline void encrypt(u32 K[40], u32 S[4][256], BYTE CT[16], BYTE PT[16]){
    
 static u32 R0, R1, R2, R3;
 static u32 T0, T1;

    /* load/byteswap/whiten input */
    R3 = K[3] ^ BSWAP(((u32*)PT)[3]);
    R2 = K[2] ^ BSWAP(((u32*)PT)[2]);
    R1 = K[1] ^ BSWAP(((u32*)PT)[1]);
    R0 = K[0] ^ BSWAP(((u32*)PT)[0]);

    ENC_ROUND(R0, R1, R2, R3, 0);
    ENC_ROUND(R2, R3, R0, R1, 1);
    ENC_ROUND(R0, R1, R2, R3, 2);
    ENC_ROUND(R2, R3, R0, R1, 3);
    ENC_ROUND(R0, R1, R2, R3, 4);
    ENC_ROUND(R2, R3, R0, R1, 5);
    ENC_ROUND(R0, R1, R2, R3, 6);
    ENC_ROUND(R2, R3, R0, R1, 7);
    ENC_ROUND(R0, R1, R2, R3, 8);
    ENC_ROUND(R2, R3, R0, R1, 9);
    ENC_ROUND(R0, R1, R2, R3, 10);
    ENC_ROUND(R2, R3, R0, R1, 11);
    ENC_ROUND(R0, R1, R2, R3, 12);
    ENC_ROUND(R2, R3, R0, R1, 13);
    ENC_ROUND(R0, R1, R2, R3, 14);
    ENC_ROUND(R2, R3, R0, R1, 15);

    /* load/byteswap/whiten output */
    ((u32*)CT)[3] = BSWAP(R1 ^ K[7]);
    ((u32*)CT)[2] = BSWAP(R0 ^ K[6]);
    ((u32*)CT)[1] = BSWAP(R3 ^ K[5]);
    ((u32*)CT)[0] = BSWAP(R2 ^ K[4]);
    
} /* End of encrypt() */











/** the key schedule routine                                                  */
void keySched(BYTE M[], int N, u32 **S, u32 K[40], int *k){
    
 static u32 Mo[4], Me[4];
 int i, j;
 static BYTE vector[8];
 static u32 A, B;

    *k = (N + 63) / 64;
    *S = (u32*)malloc(sizeof(u32) * (*k));

    for (i = 0; i < *k; i++){
	    Me[i] = BSWAP(((u32*)M)[2*i]);
	    Mo[i] = BSWAP(((u32*)M)[2*i+1]);
    }

    for (i = 0; i < *k; i++){
	    for (j = 0; j < 4; j++) vector[j] = _b(Me[i], j);
	    for (j = 0; j < 4; j++) vector[j+4] = _b(Mo[i], j);
	    (*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }
    
    for (i = 0; i < 20; i++){
	    A = h(2*i*RHO, Me, *k);
	    B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
	    K[2*i] = A+B;
	    K[2*i+1] = ROL(A + 2*B, 9);
    }
    
} /* End of keySched() */










/** Decrypts the first "len" byted of buffer "ciphertext" using the supplied 
  * key. The result is stored in buffer "ciphertext". If all parameters are set
  * to NULL, then the internal rk array is memset()-ed to zero. WARNING: 
  * Assuming key is 256 bits long.                                            */
int twofish_decrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len){

 static u32 *S;
 static u32 K[40];
 int k;
 int i;  
 static u32 QF[4][256];


  keySched(key, 256, &S, K, &k);
  fullKey(S, k, QF);
  free(S);

  if(len %16 != 0 || len == 0 )
    return -1;

  for (i=0; i<len; i+=16)
    decrypt(K, QF, ciphertext+i, plaintext+i);


  return 0;

} /* End of twofish_decrypt_buffer() */











/** Encrypts the first "len" byted of buffer "plaintext" using the supplied key.
  * The result is stored in buffer "ciphertext". If all parameters are set to 
  * NULL, then the internal rk array is memset()-ed to zero. WARNING: Assuming
  * key is 256 bits long.                                                     */
int twofish_encrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len){

 static u32 *S;
 static u32 K[40];
 int k;
 int i;  
 static u32 QF[4][256];
    
    
   if (ciphertext == NULL && plaintext == NULL && key == NULL && len == 0){
        memset(K, 0, 40 * sizeof(u32));
        memset(QF, 0, 4 * 256 * sizeof(u32));
        return 1;
   }
   else if (ciphertext == NULL || plaintext == NULL)
        return -1;  
 
   if(len %16 != 0 || len == 0 )
        return -2;


  keySched(key, 256, &S, K, &k);
  fullKey(S, k, QF);
  free(S);
    

  for (i=0; i<len; i+=16)
    encrypt(K, QF, ciphertext+i, plaintext+i);


  return 0;

} /* End of twofish_decrypt_buffer() */






void twofish_printHex(BYTE b[], int lim){
    
 int i;
    
  for (i=0; i<lim;i++) 
    printf("%02X", (u32)b[i]);
    
} /* End of twofish_printHex() */



/*

FILENAME:  "ecb_tbl.txt"

Electronic Codebook (ECB) Mode
Tables Known Answer Test
Tests permutation tables and MDS matrix multiply tables.

Algorithm Name:       TWOFISH
Principal Submitter:  Bruce Schneier, Counterpane Systems

==========

KEYSIZE=128

I=1
KEY=00000000000000000000000000000000
PT=00000000000000000000000000000000
CT=9F589F5CF6122C32B6BFEC2F2AE8C35A

I=2
KEY=00000000000000000000000000000000
PT=9F589F5CF6122C32B6BFEC2F2AE8C35A
CT=D491DB16E7B1C39E86CB086B789F5419

I=3
KEY=9F589F5CF6122C32B6BFEC2F2AE8C35A
PT=D491DB16E7B1C39E86CB086B789F5419
CT=019F9809DE1711858FAAC3A3BA20FBC3

I=4
KEY=D491DB16E7B1C39E86CB086B789F5419
PT=019F9809DE1711858FAAC3A3BA20FBC3
CT=6363977DE839486297E661C6C9D668EB

I=5
KEY=019F9809DE1711858FAAC3A3BA20FBC3
PT=6363977DE839486297E661C6C9D668EB
CT=816D5BD0FAE35342BF2A7412C246F752

I=6
KEY=6363977DE839486297E661C6C9D668EB
PT=816D5BD0FAE35342BF2A7412C246F752
CT=5449ECA008FF5921155F598AF4CED4D0

I=7
KEY=816D5BD0FAE35342BF2A7412C246F752
PT=5449ECA008FF5921155F598AF4CED4D0
CT=6600522E97AEB3094ED5F92AFCBCDD10

I=8
KEY=5449ECA008FF5921155F598AF4CED4D0
PT=6600522E97AEB3094ED5F92AFCBCDD10
CT=34C8A5FB2D3D08A170D120AC6D26DBFA

I=9
KEY=6600522E97AEB3094ED5F92AFCBCDD10
PT=34C8A5FB2D3D08A170D120AC6D26DBFA
CT=28530B358C1B42EF277DE6D4407FC591

I=10
KEY=34C8A5FB2D3D08A170D120AC6D26DBFA
PT=28530B358C1B42EF277DE6D4407FC591
CT=8A8AB983310ED78C8C0ECDE030B8DCA4

   :
   :
   :

I=48
KEY=137A24CA47CD12BE818DF4D2F4355960
PT=BCA724A54533C6987E14AA827952F921
CT=6B459286F3FFD28D49F15B1581B08E42

I=49
KEY=BCA724A54533C6987E14AA827952F921
PT=6B459286F3FFD28D49F15B1581B08E42
CT=5D9D4EEFFA9151575524F115815A12E0

==========

KEYSIZE=192

I=1
KEY=000000000000000000000000000000000000000000000000
PT=00000000000000000000000000000000
CT=EFA71F788965BD4453F860178FC19101

I=2
KEY=000000000000000000000000000000000000000000000000
PT=EFA71F788965BD4453F860178FC19101
CT=88B2B2706B105E36B446BB6D731A1E88

I=3
KEY=EFA71F788965BD4453F860178FC191010000000000000000
PT=88B2B2706B105E36B446BB6D731A1E88
CT=39DA69D6BA4997D585B6DC073CA341B2

I=4
KEY=88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44
PT=39DA69D6BA4997D585B6DC073CA341B2
CT=182B02D81497EA45F9DAACDC29193A65

I=5
KEY=39DA69D6BA4997D585B6DC073CA341B288B2B2706B105E36
PT=182B02D81497EA45F9DAACDC29193A65
CT=7AFF7A70CA2FF28AC31DD8AE5DAAAB63

I=6
KEY=182B02D81497EA45F9DAACDC29193A6539DA69D6BA4997D5
PT=7AFF7A70CA2FF28AC31DD8AE5DAAAB63
CT=D1079B789F666649B6BD7D1629F1F77E

I=7
KEY=7AFF7A70CA2FF28AC31DD8AE5DAAAB63182B02D81497EA45
PT=D1079B789F666649B6BD7D1629F1F77E
CT=3AF6F7CE5BD35EF18BEC6FA787AB506B

I=8
KEY=D1079B789F666649B6BD7D1629F1F77E7AFF7A70CA2FF28A
PT=3AF6F7CE5BD35EF18BEC6FA787AB506B
CT=AE8109BFDA85C1F2C5038B34ED691BFF

I=9
KEY=3AF6F7CE5BD35EF18BEC6FA787AB506BD1079B789F666649
PT=AE8109BFDA85C1F2C5038B34ED691BFF
CT=893FD67B98C550073571BD631263FC78

I=10
KEY=AE8109BFDA85C1F2C5038B34ED691BFF3AF6F7CE5BD35EF1
PT=893FD67B98C550073571BD631263FC78
CT=16434FC9C8841A63D58700B5578E8F67

   :
   :
   :

I=48
KEY=DEA4F3DA75EC7A8EAC3861A9912402CD5DBE44032769DF54
PT=FB66522C332FCC4C042ABE32FA9E902F
CT=F0AB73301125FA21EF70BE5385FB76B6

I=49
KEY=FB66522C332FCC4C042ABE32FA9E902FDEA4F3DA75EC7A8E
PT=F0AB73301125FA21EF70BE5385FB76B6
CT=E75449212BEEF9F4A390BD860A640941

==========

KEYSIZE=256

I=1
KEY=0000000000000000000000000000000000000000000000000000000000000000
PT=00000000000000000000000000000000
CT=57FF739D4DC92C1BD7FC01700CC8216F

I=2
KEY=0000000000000000000000000000000000000000000000000000000000000000
PT=57FF739D4DC92C1BD7FC01700CC8216F
CT=D43BB7556EA32E46F2A282B7D45B4E0D

I=3
KEY=57FF739D4DC92C1BD7FC01700CC8216F00000000000000000000000000000000
PT=D43BB7556EA32E46F2A282B7D45B4E0D
CT=90AFE91BB288544F2C32DC239B2635E6

I=4
KEY=D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F
PT=90AFE91BB288544F2C32DC239B2635E6
CT=6CB4561C40BF0A9705931CB6D408E7FA

I=5
KEY=90AFE91BB288544F2C32DC239B2635E6D43BB7556EA32E46F2A282B7D45B4E0D
PT=6CB4561C40BF0A9705931CB6D408E7FA
CT=3059D6D61753B958D92F4781C8640E58

I=6
KEY=6CB4561C40BF0A9705931CB6D408E7FA90AFE91BB288544F2C32DC239B2635E6
PT=3059D6D61753B958D92F4781C8640E58
CT=E69465770505D7F80EF68CA38AB3A3D6

I=7
KEY=3059D6D61753B958D92F4781C8640E586CB4561C40BF0A9705931CB6D408E7FA
PT=E69465770505D7F80EF68CA38AB3A3D6
CT=5AB67A5F8539A4A5FD9F0373BA463466

I=8
KEY=E69465770505D7F80EF68CA38AB3A3D63059D6D61753B958D92F4781C8640E58
PT=5AB67A5F8539A4A5FD9F0373BA463466
CT=DC096BCD99FC72F79936D4C748E75AF7

I=9
KEY=5AB67A5F8539A4A5FD9F0373BA463466E69465770505D7F80EF68CA38AB3A3D6
PT=DC096BCD99FC72F79936D4C748E75AF7
CT=C5A3E7CEE0F1B7260528A68FB4EA05F2

I=10
KEY=DC096BCD99FC72F79936D4C748E75AF75AB67A5F8539A4A5FD9F0373BA463466
PT=C5A3E7CEE0F1B7260528A68FB4EA05F2
CT=43D5CEC327B24AB90AD34A79D0469151

   :
   :
   :

I=48
KEY=2E2158BC3E5FC714C1EEECA0EA696D48D2DED73E59319A8138E0331F0EA149EA
PT=248A7F3528B168ACFDD1386E3F51E30C
CT=431058F4DBC7F734DA4F02F04CC4F459

I=49
KEY=248A7F3528B168ACFDD1386E3F51E30C2E2158BC3E5FC714C1EEECA0EA696D48
PT=431058F4DBC7F734DA4F02F04CC4F459
CT=37FE26FF1CF66175F5DDF4C33B97A205


*/


/* EOF */
