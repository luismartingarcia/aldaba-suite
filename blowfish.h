
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
/**************************************************************************/
/*                                                                        */
/* Blowfish Encryption Algorithm (Bruce Schneier).                        */
/*                                                                        */
/* Implemented by Paul Kocher.                                            */
/*   --> http://www.cryptography.com/company/Paul-Kocher.html             */
/*                                                                        */
/* Modified by Luis Martin Garcia. December 15, 2007.                     */
/*   --> aldabaknocking [.at.] gmail.com                                  */
/*   --> http://www.aldabaknocking.com                                    */
/*                                                                        */
/* Original implementation available at:                                  */
/*   --> http://www.schneier.com/code/bfsh-koc.zip                        */
/*                                                                        */
/* Original Blowfish paper:                                               */
/*   B. Schneier. Description of a New Variable-Length Key, 64-Bit Block  */
/*   Cipher (Blowfish). Fast Software Encryption, Cambridge Security      */
/*   Workshop Proceedings (December 1993), Springer-Verlag, 1994,         */
/*   pp. 191-204.                                                         */
/*   http://www.schneier.com/paper-blowfish-fse.html                      */
/*                                                                        */
/**************************************************************************/
/*                                                                        */
/* Original documentation:                                                */
/*                                                                        */
/* COMMENTS ON USING THIS CODE:                                           */
/*                                                                        */
/* Normal usage is as follows:                                            */
/*   [1] Allocate a BLOWFISH_CTX.  (It may be too big for the stack.)     */
/*   [2] Call Blowfish_Init with a pointer to your BLOWFISH_CTX, a        */
/*       pointer to the key, and the number of bytes in the key.          */
/*   [3] To encrypt a 64-bit block, call Blowfish_Encrypt with a pointer  */
/*       to BLOWFISH_CTX, a pointer to the 32-bit left half of the        */
/*	     plaintext and a pointer to the 32-bit right half.  The plaintext */
/*	     will be overwritten with the ciphertext.                         */
/*   [4] Decryption is the same as encryption except that the plaintext   */
/*       and ciphertext are reversed.                                     */
/*                                                                        */
/* Warning #1:  The code does not check key lengths. (Caveat encryptor.)  */
/* Warning #2:  Beware that Blowfish keys repeat such that "ab" = "abab". */
/* Warning #3:  It is normally a good idea to zeroize the BLOWFISH_CTX    */
/*              before freeing it.                                        */
/* Warning #4:  Endianness conversions are the responsibility of the      */
/*              caller. (To encrypt bytes on a little-endian platforms,   */
/*              you'll probably want to swap bytes around instead of just */
/*              casting.)                                                 */
/* Warning #5:  Make sure to use a reasonable mode of operation for your  */
/*              application. (If you don't know what CBC mode is, see     */
/*              Warning #7.)                                              */
/* Warning #6:  This code is susceptible to timing attacks.               */
/* Warning #7:  Security engineering is risky and non-intuitive.  Have    */
/*              someone check your work. If you don't know what you are   */
/*              doing, get help.                                          */
/*                                                                        */
/* This is code is fast enough for most applications, but is not optimized*/
/* for speed.                                                             */
/*                                                                        */
/* If you require this code under a license other than LGPL, please ask.  */
/* I can be located using your favorite search engine. Unfortunately, I   */
/* do not have time to provide unpaid support for everyone who uses this  */
/* code.                                                                  */
/*                                                                        */
/*                                             -- Paul Kocher             */
/*                                                                        */
/**************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)              */
/*                                                                        */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)       */
/* $DESCRIPTION                                                           */
/*                                                                        */
/**************************************************************************/
/** \file blowfish.h 
  * \brief Blowfish cipher. */
  
/** \brief Blowfish cipher context variable. */
typedef struct {
  unsigned long P[16 + 2];
  unsigned long S[4][256];
} BLOWFISH_CTX;             

void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *plain_xl, uint32_t *plain_xr, uint32_t *cipher_xl, uint32_t *cipher_xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *plain_xl, uint32_t *plain_xr, uint32_t *cipher_xl, uint32_t *cipher_xr);
int blowfish_encrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);
int blowfish_decrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);

/* EOF */
