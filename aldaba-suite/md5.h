
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
/**************************************************************************/
/** \file md5.h 
  * \brief MD5 hashing algorithm. */


#ifndef MD5_H
#define MD5_H

#include <sys/types.h>

typedef unsigned int uint32;

/** \brief MD5 context information. */
typedef struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    unsigned char in[64];
    int doByteReverse;
}MD5Context;


/* Initialize MD5 hash.Set bit count to 0 and buffer to mysterious  */
/* initialization constants.                                        */
/* parameter "ctx" is a pointer to a MD5 private data structure;    */
/* "brokenEndian" lets user calculate broken MD5 sums (if true)     */
void md5_init( struct MD5Context * ctx, int brokenEndian);


/* Update context to reflect the concatenation of another buffer full of bytes*/
/* parameter "ctx" is a pointer to a MD5 private data structure; "buf" is the */
/* next data buffer and "len" is the length of "buf" in bytes                 */
void md5_update(struct MD5Context * ctx, unsigned char const *buf, unsigned len);


/* Return MD5 digest, and reset context. */
void md5_final(unsigned char digest[16], struct MD5Context * ctx);


/* The core of the MD5 algorithm.This alters an existing MD5 hash to reflect */
/* the addition of 16 longwords of new data.                                 */
/* parameter "buf" are current MD5 variables; "in" is the next block of data */
void md5_transform(uint32 buf[4], uint32 const in[16]);

/* Get the md5sum of the supplied buffer.                                    */
void md5sum(unsigned char *buffer, unsigned len, unsigned char *MD5digest);

/* Print the 16-byte buffer pointed by MD5digest to stodout in Hex format */
int md5_printHash(unsigned char *MD5digest);


#endif    /* MD5_H */

/* EOF */
