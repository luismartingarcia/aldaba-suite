
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
/* Rijndael Encryption Algorithm. (Joan Daemen and Vincent Rijmen)        */
/*                                                                        */
/* Implemented by Philip J. Erdelsky. September 3, 2002.                  */
/*   --> pje [.at.] efgh.com                                              */
/*   --> http://www.alumni.caltech.edu/~pje/                              */
/*                                                                        */
/* Modified by Luis Martin Garcia. December 5, 2007.                      */
/*   --> aldabaknocking [.at.] gmail.com                                  */
/*   --> http://www.aldabaknocking.com                                    */
/*                                                                        */
/* Original implementation available at:                                  */
/*   --> http://www.efgh.com/software/rijndael.htm                        */
/*                                                                        */
/* Original Rijndael paper:                                               */
/*   Joan Daemen, Vincent Rijmen. The block cipher Rijndael.              */
/*   CARDIS 1998, LNCS 1820, pp. 247-256, 2000.                           */
/*   http://www.iaik.tugraz.at/aboutus/people/rijmen/tekst.ps             */
/*                                                                        */    
/**************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)              */
/*                                                                        */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)       */
/* $DESCRIPTION                                                           */
/*                                                                        */
/**************************************************************************/
/** \file rijndael.h 
  * \brief Rijndael/AES cipher. */


#ifndef H__RIJNDAEL
#define H__RIJNDAEL

int rijndaelSetupEncrypt(uint32_t *rk, const unsigned char *key, int keybits);
int rijndaelSetupDecrypt(uint32_t *rk, const unsigned char *key,int keybits);
void rijndaelEncrypt(const uint32_t *rk, int nrounds,const unsigned char plaintext[16], unsigned char ciphertext[16]);
void rijndaelDecrypt(const uint32_t *rk, int nrounds,const unsigned char ciphertext[16], unsigned char plaintext[16]);
int rijndael_encrypt16(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key);
int rijndael_decrypt16(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key);
int rijndael_encrypt32(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key);
int rijndael_decrypt32(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key);
int rijndael_encrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);
int rijndael_decrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);


#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

#endif
