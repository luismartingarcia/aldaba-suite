
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
/* C implementation of the Serpent encryption algorithm.                  */
/* Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen.             */
/*                                                                        */
/* This library is free software; you can redistribute it and/or modify   */
/* it under the terms of the GNU General Public License as published by   */
/* the Free Software Foundation; either version 2 of the License, or      */
/* any later version.                                                     */
/*                                                                        */
/* This library is distributed in the hope that it will be useful, but    */
/* WITHOUT ANY WARRANTY; without even the implied warranty of             */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      */
/* General Public License for more details.                               */
/*                                                                        */
/* You should have received a copy of the GNU General Public License      */
/* along with Aldaba; if not, write to the Free Software Foundation,      */
/* Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA         */
/*                                                                        */    
/* Serpent Encryption Algorithm. (Ross Anderson, Eli Biham, Lars Knudsen) */
/*                                                                        */
/* Implemented by Ross Anderson, Eli Biham and Lars Knudsen.              */
/*   --> http://www.cl.cam.ac.uk/~rja14/serpent.html                      */
/*                                                                        */
/* Modified by Luis Martin Garcia. December 5, 2007.                      */
/*   --> aldabaknocking [.at.] gmail.com                                  */
/*   --> http://www.aldabaknocking.com                                    */
/*                                                                        */
/* Original implementation available at:                                  */
/*   --> http://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz             */
/*                                                                        */
/* Original Serpent paper:                                                */
/*   Ross Anderson, Eli Biham and Lars Knudsen.                           */
/*   Serpent: A Proposal for the Advanced Encryption Standard.            */ 
/*   http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf                    */
/*                                                                        */   
/**************************************************************************/
/* This file is the result of merging files aes.h and serpentboxes.h      */
/*                                                                        */   
/* Original Documentation:                                                */
/*                                                                        */   
/*  aes.h                                                                 */
/*                                                                        */   
/*  AES Cipher header file for ANSI C Submissions                         */
/*  Lawrence E. Bassham III                                               */
/*  Computer Security Division                                            */
/*  National Institute of Standards and Technology                        */
/*                                                                        */
/*  April 15, 1998                                                        */
/*                                                                        */
/*  This sample is to assist implementers developing to the Cryptographic */
/*  API Profile for AES Candidate Algorithm Submissions.  Please consult  */
/*  this document as a cross-reference.                                   */
/*                                                                        */
/*  ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE  */
/*  MUST BE DOCUMENTED.  CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH*/
/*  THE STRING "CHANGE POSSIBLE".  FUNCTION CALLS AND THEIR PARAMETERS    */
/*  CANNOT BE CHANGED.  STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS   */
/*  TO INCLUDE IMPLEMENTATION SPECIFIC INFORMATION.                       */
/*                                                                        */
/**************************************************************************/
/* COMMENTS/CHANGELOG: (Please comment any relevant changes)              */
/*                                                                        */
/* $MONTH $DAY, $YEAR. Developer: $NAME ($DEVELOPER@E-MAIL.ADDRESS)       */
/* $DESCRIPTION                                                           */
/*                                                                        */
/**************************************************************************/
/** \file serpent.h
  * \brief Serpent cipher. */


/* Start of aes.h */

/*  Defines: Add any additional defines you need                              */
#define     DIR_ENCRYPT     0    /*  Are we encrpyting?                       */
#define     DIR_DECRYPT     1    /*  Are we decrpyting?                       */
#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?            */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?            */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode?      */
#define     TRUE            1
#define     FALSE           0

/*  Error Codes - CHANGE POSSIBLE: inclusion of additional error codes        */
#define     BAD_KEY_DIR      -1  /*  Key direction is invalid                 */
#define     BAD_KEY_MAT      -2  /*  Key material not of correct length       */
#define     BAD_KEY_INSTANCE -3  /*  Key passed is not valid                  */
#define     BAD_CIPHER_MODE  -4  /*  Params passed to cipherInit invalid      */
#define     BAD_CIPHER_STATE -5  /*  Cipher in wrong state (not initialized)  */

/*  CHANGE POSSIBLE:  inclusion of algorithm specific defines                 */
#define     MAX_KEY_SIZE	64  /* # of ASCII chars needed to represent a key */
#define     MAX_IV_SIZE		32  /* # of ASCII chars needed to represent an IV */

/*  Typedefs:                                                                 */
/*  Typedef'ed data storage elements.  Add any algorithm specific parameters  */
/*  at the bottom of the structs as appropriate.                              */
//typedef unsigned char BYTE;



/** \brief  Serpent Cipher. Structure for key information */
typedef struct {
      uint8_t  direction;	/**<  Key used for encrypting or decrypting? */
      int   keyLen;	/**<  Length of the key  */
      char  keyMaterial[MAX_KEY_SIZE+1];  /**<  Raw key data in ASCII, e.g., what the user types or KAT values)*/
      /*  The following parameters are algorithm dependent, replace or add as necessary  */
      uint32_t key[8];             /**< The key in binary */
      uint32_t subkeys[33][4];	/**< Serpent subkeys */
} keyInstance;

/** \brief Serpent Cipher. Structure for cipher information */
typedef struct {
      uint8_t	mode;           /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
      char  IV[MAX_IV_SIZE]; 	/* A possible Initialization Vector for ciphering */
      /*  Add any algorithm specific parameters needed here  */
      int   blockSize;    	/* Sample: Handles non-128 bit block sizes (if available) */
} cipherInstance;


/*  Function protoypes  */
int makeKey(keyInstance *key, uint8_t direction, int keyLen, const char *keyMaterial);
int cipherInit(cipherInstance *cipher, uint8_t mode, char *IV);
int blockEncrypt(cipherInstance *cipher, keyInstance *key, uint8_t *input, int inputLen, uint8_t *outBuffer);
int blockDecrypt(cipherInstance *cipher, keyInstance *key, uint8_t *input, int inputLen, uint8_t *outBuffer);
void serpent_encrypt(uint32_t plaintext[4], uint32_t ciphertext[4], uint32_t subkeys[33][4]);
void serpent_decrypt(uint32_t ciphertext[4],uint32_t plaintext[4],	uint32_t subkeys[33][4]);
int serpent_encrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);
int serpent_decrypt_buffer(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, int len);

/* End of aes.h */




/* EOF  */
