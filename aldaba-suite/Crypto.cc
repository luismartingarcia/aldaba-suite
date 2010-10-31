
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
#include "Crypto.h"
#include "md5.h"
#include "output.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "blowfish.h"
#include "twofish.h"
#include "rijndael.h"
#include "serpent.h"
#include "tools.h"
#include "crypto_pbkdf2.h"


/** Tests the correctness of every crypto function used in Aldaba Knocking
  * Suite. It returns OP_SUCCESS if everything works as expected and OP_FAILURE
  * in case of error.                                                         */
int Crypto::test(void){
 if ( test_twofish() != OP_SUCCESS )
    return OP_FAILURE;
 if ( test_serpent() != OP_SUCCESS )
    return OP_FAILURE;
 if ( test_rijndael() != OP_SUCCESS )
    return OP_FAILURE;
 if ( test_sha256() != OP_SUCCESS )
    return OP_FAILURE;
 if ( test_md5() != OP_SUCCESS )
    return OP_FAILURE;
 if ( test_blowfish() != OP_SUCCESS )
    return OP_FAILURE;
 if( test_hmacsha256() != OP_SUCCESS)
     return OP_FAILURE;
 if( test_pbkdf2_sha256() != OP_SUCCESS)
     return OP_FAILURE;
 return OP_SUCCESS;
} /* End of test_crypto() */


/** Tests Serpent cipher against a known test vector. It returns OP_SUCCESS if
  * everything works as expected and OP_FAILURE in case of error.             */
int Crypto::test_serpent(void){
 /* Serpent test vector. Set 8, vector#0.
    KEY=000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    PT=3DA46FFA6F4D6F30CD258333E5A61369
    CT=00112233445566778899AABBCCDDEEFF
    Source: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
 */
 unsigned char e_key[32]=
              {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
               0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
               0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
 unsigned char cipher[16]=
              {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
               0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
 unsigned char expected_plain[16]=
              {0x3D,0xA4,0x6F,0xFA,0x6F,0x4D,0x6F,0x30,
               0xCD,0x25,0x83,0x33,0xE5,0xA6,0x13,0x69};
 unsigned char computed_plain[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char computed_cipher[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 /* Test decryption */
 serpent_decrypt_buffer(cipher, computed_plain, e_key, 16);
 if( memcmp(expected_plain, computed_plain, 16) != 0 )
    return OP_FAILURE;

  /* Test encryption */
  serpent_encrypt_buffer(computed_cipher, expected_plain, e_key, 16);
  if( memcmp(cipher, computed_cipher, 16) != 0 )
    return OP_FAILURE;

  return OP_SUCCESS;
} /* End of test_serpent() */


/** Tests Twofish cipher against a known test vector. It returns OP_SUCCESS if
  * everything works as expected and OP_FAILURE in case of error.             */
int Crypto::test_twofish(void){
 /* Twofish test vector I=7 / 256-bit
    KEY=3059D6D61753B958D92F4781C8640E586CB4561C40BF0A9705931CB6D408E7FA
    PT=E69465770505D7F80EF68CA38AB3A3D6
    CT=5AB67A5F8539A4A5FD9F0373BA463466
    Source: http://www.schneier.com/code/ecb_ival.txt
 */
 unsigned char e_key[32]=
              {0x30,0x59,0xD6,0xD6,0x17,0x53,0xB9,0x58,
               0xD9,0x2F,0x47,0x81,0xC8,0x64,0x0E,0x58,
               0x6C,0xB4,0x56,0x1C,0x40,0xBF,0x0A,0x97,
               0x05,0x93,0x1C,0xB6,0xD4,0x08,0xE7,0xFA};
 unsigned char cipher[16]=
              {0x5A,0xB6,0x7A,0x5F,0x85,0x39,0xA4,0xA5,
               0xFD,0x9F,0x03,0x73,0xBA,0x46,0x34,0x66};
 unsigned char expected_plain[16]=
              {0xE6,0x94,0x65,0x77,0x05,0x05,0xD7,0xF8,
               0x0E,0xF6,0x8C,0xA3,0x8A,0xB3,0xA3,0xD6};
 unsigned char computed_plain[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char computed_cipher[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

 /* Test decryption */
  twofish_decrypt_buffer(cipher, computed_plain, e_key, 16);
  if( memcmp((char *)expected_plain, computed_plain, 16) != 0 )
    return OP_FAILURE;

  /* Test encryption */
  twofish_encrypt_buffer(computed_cipher, expected_plain, e_key, 16);

  if( memcmp(cipher, computed_cipher, 16) != 0 )
    return OP_FAILURE;
  else
    return OP_SUCCESS;

} /* End of test_twofish() */


/** Tests Rijndael/AES cipher against a known test vector. It returns OP_SUCCESS
  * if everything works as expected and OP_FAILURE in case of error.          */
int Crypto::test_rijndael(void){
 /* Rijndael test vector I=7 / 256-bit -- File: ecb_tbl.txt
    KEY=F0F1F2F3F5F6F7F8FAFBFCFDFE01000204050607090A0B0C0E0F101113141516
    PT=B8358E41B9DFF65FD461D55A99266247
    CT=92097B4C88A041DDF98144BC8D22E8E7
    Source: http://www.iaik.tugraz.at/research/krypto/aes/old/~rijmen/rijndael/testvalues.tar.gz
 */
 unsigned char e_key[32]=
              {0xF0,0xF1,0xF2,0xF3,0xF5,0xF6,0xF7,0xF8,
               0xFA,0xFB,0xFC,0xFD,0xFE,0x01,0x00,0x02,
               0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C,
               0x0E,0x0F,0x10,0x11,0x13,0x14,0x15,0x16};
 unsigned char cipher[16]=
              {0x92,0x09,0x7B,0x4C,0x88,0xA0,0x41,0xDD,
               0xF9,0x81,0x44,0xBC,0x8D,0x22,0xE8,0xE7};
 unsigned char expected_plain[16]=
              {0xB8,0x35,0x8E,0x41,0xB9,0xDF,0xF6,0x5F,
               0xD4,0x61,0xD5,0x5A,0x99,0x26,0x62,0x47};
 unsigned char computed_plain[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char computed_cipher[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  /* Test decryption */
  rijndael_decrypt_buffer(cipher, computed_plain, e_key, 16);
  if( memcmp(expected_plain, computed_plain, 16) != 0 )
    return OP_FAILURE;

  /* Test encryption */
  rijndael_encrypt_buffer(computed_cipher, expected_plain, e_key, 16);
  if( memcmp(cipher, computed_cipher, 16) != 0 )
    return OP_FAILURE;

  return OP_SUCCESS;
} /* End of test_rijndael() */


/** Tests Blowfish cipher against a known test vector. It returns OP_SUCCESS if
  * everything works as expected and OP_FAILURE in case of error.             */
int Crypto::test_blowfish(void){
 /* Blowfish test vector
    KEY=0000000000000000000000000000000000000000000000000000000000000000
    PT=0000000000000000
    CT=4597F94E78DD9861
    Source: http://www.mirrors.wiretapped.net/security/cryptography/algorithms/blowfish/blowfish-TESTVECTORS.txt
 */
 unsigned char e_key[32]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char cipher[8]=
              {0x45,0x97,0xF9,0x4E,0x78,0xDD,0x98,0x61};
 unsigned char expected_plain[8]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char computed_plain[8]=
              {0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 unsigned char computed_cipher[8]=
              {0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  /* Test decryption */
  blowfish_decrypt_buffer(cipher, computed_plain, e_key, 8);
  if( memcmp(expected_plain, computed_plain, 8) != 0 )
    return OP_FAILURE;

  /* Test encryption */
  blowfish_encrypt_buffer(computed_cipher, expected_plain, e_key, 8);
  if( memcmp(cipher, computed_cipher, 8) != 0 )
    return OP_FAILURE;

  return OP_SUCCESS;
} /* End of test_blowfish() */


/** Tests SHA256 hashing algorithm against a known test vector. It returns
  * OP_SUCCESS if everything works as expected and OP_FAILURE in case of
  * error.                                                                    */
int Crypto::test_sha256(void){
 /* SHA256 test vector
    PT="Aldaba Knocking Suite"
    HASH=4f17dbddc022ba043327fca882e10261476f762d03cd759616ca17cdbf626618
    Source: None.
 */
 unsigned char text[]={"Aldaba Knocking Suite"};
 unsigned char expected_hash[32]=
              {0x4f,0x17,0xdb,0xdd,0xc0,0x22,0xba,0x04,
               0x33,0x27,0xfc,0xa8,0x82,0xe1,0x02,0x61,
               0x47,0x6f,0x76,0x2d,0x03,0xcd,0x75,0x96,
               0x16,0xca,0x17,0xcd,0xbf,0x62,0x66,0x18};
 unsigned char computed_hash[32]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

 SHA256::sha256sum(text, strlen( (char *)text), computed_hash);
 if( memcmp(computed_hash, expected_hash, 32) != 0 )
    return OP_FAILURE;
 return OP_SUCCESS;
} /* End of test_sha256() */


/** Tests MD5 hashing algorithm against a known test vector.
  * @return OP_SUCCESS if everything works as expected.
  * @return OP_FAILURE in case of error.                                      */
int Crypto::test_md5(void){
 /* MD5 test vector
    PT="Aldaba Knocking Suite"
    HASH=fb6cbeec382335fd6b0ab9d327225d2c
    Source: None.
 */
 unsigned char text[]={"Aldaba Knocking Suite"};
 unsigned char expected_hash[16]=
              {0xfb,0x6c,0xbe,0xec,0x38,0x23,0x35,0xfd,
               0x6b,0x0a,0xb9,0xd3,0x27,0x22,0x5d,0x2c};
 unsigned char computed_hash[16]=
              {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  md5sum(text, strlen( (char *)text), computed_hash);
  if( memcmp(computed_hash, expected_hash, 15) != 0 )
    return OP_FAILURE;
  return OP_SUCCESS;
} /* End of test_md5() */


/** Tests HMAC_SHA256 algorithm against known test vectors. It returns
  * OP_SUCCESS if everything works as expected and OP_FAILURE in case of error. */
int Crypto::test_hmacsha256(void){
 /* Test vector 1
    Key =  0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    Data = 4869205468657265
    HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    Source: RFC 4231, HMAC-SHA Identifiers and Test Vectors. http://www.ietf.org/rfc/rfc4231.txt
 */
  u8 computed_mac[32];
  u8 key1[] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
               0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
  u8 data1[]= {0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
  u8 mac1[] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,
               0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,
               0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,
               0xcf,0xf7};
  HMAC_SHA256::hmac_sha256(key1, sizeof(key1), data1, sizeof(data1), computed_mac, 32);
  if(memcmp(computed_mac, mac1, 32)!=0)
      return OP_FAILURE;

 /* Test vector 2
    Key =  4a656665
    Data = 7768617420646f2079612077616e7420666f72206e6f7468696e673f
    HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    Source: RFC 4231, HMAC-SHA Identifiers and Test Vectors. http://www.ietf.org/rfc/rfc4231.txt
 */
  u8 key2[] =  {0x4a,0x65, 0x66, 0x65};
  u8 data2[] = {0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,0x79,0x61,
                0x20,0x77,0x61,0x6e,0x74,0x20,0x66,0x6f,0x72,0x20,
                0x6e,0x6f,0x74,0x68,0x69,0x6e,0x67,0x3f};
  u8 mac2[]=   {0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,
                0x24,0x26,0x08,0x95,0x75,0xc7,0x5a,0x00,0x3f,0x08,
                0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,
                0x38,0x43};
  HMAC_SHA256::hmac_sha256(key2, sizeof(key2), data2, sizeof(data2), computed_mac, 32);
  if(memcmp(computed_mac, mac2, 32)!=0)
      return OP_FAILURE;

 /* Test vector 3
    Key  = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    Data = dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
           dddddddddddddddddddddddddddddddddddd
    HMAC = 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
    Source: RFC 4231, HMAC-SHA Identifiers and Test Vectors. http://www.ietf.org/rfc/rfc4231.txt
 */
  u8 key3[] = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
               0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
  u8 data3[]= {0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
               0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
               0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
               0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
               0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd};
  u8 mac3[]=  {0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,
               0xb8,0xeb,0xd0,0x91,0x81,0xa7,0x29,0x59,0x09,0x8b,
               0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,
               0x65,0xfe};
  HMAC_SHA256::hmac_sha256(key3, sizeof(key3), data3, sizeof(data3), computed_mac, 32);
  if(memcmp(computed_mac, mac3, 32)!=0)
      return OP_FAILURE;

  return OP_SUCCESS;
} /* End of test_hmacsha256() */


/** Tests PBKDF2-SHA256 algorithm against a known test vector. It returns
  * OP_SUCCESS if everything works as expected and OP_FAILURE in case of error. */
int Crypto::test_pbkdf2_sha256(void){
 /* Test vector
    Password="password"
    Salt=78578e5a5d63cb06
    Key=97b5a91d35af542324881315c4f849e327c4707d1bc9d322
    Source: CryptoSys API Library Manual. http://www.cryptosys.net/manapi/api_PBE_Kdf2.html
 */
  u8 computed_key[24];
  char password[]={"password"};
  u8 salt[8]={0x78,0x57,0x8E,0x5A,0x5D,0x63,0xCB,0x06};
  u8 expected_key[24]={0x97,0xb5,0xa9,0x1d,0x35,0xaf,0x54,0x23,
                       0x24,0x88,0x13,0x15,0xc4,0xf8,0x49,0xe3,
                       0x27,0xc4,0x70,0x7d,0x1b,0xc9,0xd3,0x22};
  PBKDF2::pbkdf2_sha256((u8 *)password, strlen(password), salt, 8, 24, computed_key, 2048);
  if(memcmp(computed_key, expected_key, 24)!=0)
    return OP_FAILURE;

  return OP_SUCCESS;
} /* End of test_pbkdf2_sha256() */
        

/** Encrypts the first "len" bytes of buffer "plaintext" in CBC Mode using the
  * supplied key. The result is stored in buffer "ciphertext".
  * @param plaintext Buffer that contains the data to be encrypted.
  * @param ciphertext Buffer where the ciphertext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied plaintext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of plaintext must be a multiple of the cipher block size
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::encrypt_buffer_cbc(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){
  unsigned char nullblock[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  unsigned char buffer[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  u8 *prevciphertext=NULL;
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

 /* Set initialization vector */
 if (initial_IV == NULL )
    prevciphertext=nullblock;  /* Set IV to a block of zeroes */
 else
    prevciphertext=initial_IV; /* IV was supplied by the caller */

  /* Iterate through each cipher block */
  for (i=0; i<len; i+=blocksize, plaintext+=blocksize, ciphertext+=blocksize){

     for (j = 0; j < blocksize; j++){
        buffer[j] = plaintext[j] ^ prevciphertext[j]; /* XOR plaintext block and previous ciphertext block */
     }

     switch(algorithm){

        case ALG_BLOWFISH:
            if ( blowfish_encrypt_buffer(ciphertext, buffer, key, blocksize) != 0)
                return -1;
        break;

        case ALG_TWOFISH:
            if ( twofish_encrypt_buffer(ciphertext, buffer, key, blocksize) != 0)
                return -1;
        break;

        case ALG_RIJNDAEL:
            if ( rijndael_encrypt_buffer(ciphertext, buffer, key, blocksize) != 0)
                return -1;
        break;

        case ALG_SERPENT:
            if ( serpent_encrypt_buffer(ciphertext, buffer, key, blocksize) != 0)
                return -1;
        break;

        default:
             return -3;
        break;
     }
    prevciphertext=ciphertext;
  }
  return OP_SUCCESS;
} /* End of encrypt_buffer_cbc() */


/** Decrypts the first "len" bytes of buffer "ciphertext" in CBC Mode using the
  * supplied key. The result is stored in buffer "plaintext".
  * @param ciphertext Buffer that contains the data to be decrypted.
  * @param plaintext Buffer where the plaintext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied ciphertext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of ciphertext must be a multiple of the cipher block size.
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::decrypt_buffer_cbc(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){

  unsigned char nullblock[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  u8 *prevciphertext=NULL;
  u8 *auxcipher=NULL;
  u8 *auxplain=NULL;
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

 /* If IV not supplied set it to a block of zeroes */
 if (initial_IV == NULL )
    initial_IV=nullblock;

  auxcipher = ciphertext + len - blocksize; /* Set auxiliar pointers */
  auxplain = plaintext + len - blocksize;

 /* Iterate through each cipher block, backwards */
 for (i=len; i>0; i-=blocksize, auxcipher-=blocksize, auxplain-=blocksize){

    switch(algorithm){

        case ALG_BLOWFISH:
            if ( blowfish_decrypt_buffer(auxcipher, auxplain, key, blocksize) != 0)
                break;
        break;

        case ALG_TWOFISH:
            if ( twofish_decrypt_buffer(auxcipher, auxplain, key, blocksize) != 0)
                break;
        break;

        case ALG_RIJNDAEL:
            if ( rijndael_decrypt_buffer(auxcipher, auxplain, key, blocksize) != 0)
                break;
        break;

        case ALG_SERPENT:
            if ( serpent_decrypt_buffer(auxcipher, auxplain, key, blocksize) != 0)
                break;
        break;

        default:
             return -3;
        break;
    }
       /* Set "XOR-text" */
       prevciphertext = (i<=blocksize) ? initial_IV : auxcipher-blocksize;

       /* Compute (decipheredText XOR previuousCipherText) to obtain plaintext */
       for (j = 0; j < blocksize; j++){
            auxplain[j] ^= prevciphertext[j]; /* XOR plaintext block and previous ciphertext block */
       }
 }
  return OP_SUCCESS;
} /* End of decrypt_buffer_cbc() */


/** Encrypts the first "len" bytes of buffer "plaintext" in CFB Mode using the
  * supplied key. The result is stored in buffer "ciphertext".
  * @param plaintext Buffer that contains the data to be encrypted.
  * @param ciphertext Buffer where the ciphertext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied plaintext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of plaintext must be a multiple of the cipher block size
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::encrypt_buffer_cfb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){
  unsigned char nullblock[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  unsigned char buffer[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  unsigned char backup[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  u8 *prevciphertext=NULL;
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

 /* Set initialization vector */
 if (initial_IV == NULL )
    prevciphertext=nullblock;  /* Set IV to a block of zeroes */
 else
    prevciphertext=initial_IV; /* IV was supplied by the caller */

  /* Iterate through each cipher block */
  for (i=0; i<len; i+=blocksize, plaintext+=blocksize, ciphertext+=blocksize){

     switch(algorithm){

        case ALG_BLOWFISH:
            if ( blowfish_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_TWOFISH:
            if ( twofish_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_RIJNDAEL:
            if ( rijndael_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_SERPENT:
            if ( serpent_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        default:
             return -3;
        break;
     }

     for (j = 0; j < blocksize; j++){
        ciphertext[j] = plaintext[j] ^ buffer[j]; /* XOR plaintext block and computed cipher block */
     }

    /* We need to backup last ciphertext in case the caller uses the same
       buffer for plaintext and ciphertext */
    memcpy(backup, ciphertext, blocksize);
    prevciphertext=backup;

  }
  return OP_SUCCESS;
} /* End of encrypt_buffer_cfb() */


/** Decrypts the first "len" bytes of buffer "ciphertext" in CFB Mode using the
  * supplied key. The result is stored in buffer "plaintext".
  * @param ciphertext Buffer that contains the data to be decrypted.
  * @param plaintext Buffer where the plaintext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied ciphertext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of ciphertext must be a multiple of the cipher block size.
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::decrypt_buffer_cfb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){
  unsigned char nullblock[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  unsigned char buffer[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  unsigned char backup[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  u8 *prevciphertext=NULL;
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

 /* Set initialization vector */
 if (initial_IV == NULL )
    prevciphertext=nullblock;  /* Set IV to a block of zeroes */
 else
    prevciphertext=initial_IV; /* IV was supplied by the caller */

  /* Iterate through each cipher block */
  for (i=0; i<len; i+=blocksize, plaintext+=blocksize, ciphertext+=blocksize){

     switch(algorithm){

        case ALG_BLOWFISH:
            if ( blowfish_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_TWOFISH:
            if ( twofish_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_RIJNDAEL:
            if ( rijndael_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        case ALG_SERPENT:
            if ( serpent_encrypt_buffer(buffer, prevciphertext, key, blocksize) != 0)
                return -1;
        break;

        default:
             return -3;
        break;
     }

     /* We need to backup last ciphertext in case the caller uses the same
        buffer for plaintext and ciphertext */
     memcpy(backup, ciphertext, blocksize);
     prevciphertext=backup;

     for (j = 0; j < blocksize; j++){
        plaintext[j] = ciphertext[j] ^ buffer[j]; /* XOR plaintext block and computed cipher block */
     }
  }
  return OP_SUCCESS;
} /* End of decrypt_buffer_cfb() */


/** Encrypts the first "len" bytes of buffer "plaintext" in OFB Mode using the
  * supplied key. The result is stored in buffer "ciphertext".
  * @param plaintext Buffer that contains the data to be encrypted.
  * @param ciphertext Buffer where the ciphertext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied plaintext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of plaintext must be a multiple of the cipher block size
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::encrypt_buffer_ofb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){
  unsigned char O_vector[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;


  /* Iterate through each cipher block */
  for (i=0; i<len; i+=blocksize, plaintext+=blocksize, ciphertext+=blocksize){

     if(i==0){
         /* Set initialization vector */
         if (initial_IV == NULL )
            memset(O_vector, 0, blocksize);
         else
            memcpy(O_vector,initial_IV, blocksize); /* IV was supplied by the caller */
     }

     /* Compute 0_vector_i = Ek( O_vector_i-1 )*/
     switch(algorithm){

            case ALG_BLOWFISH:
                if ( blowfish_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_TWOFISH:
                if ( twofish_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_RIJNDAEL:
                if ( rijndael_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_SERPENT:
                if ( serpent_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            default:
                 return -3;
            break;
        }


     for (j = 0; j < blocksize; j++){
        ciphertext[j] = plaintext[j] ^ O_vector[j]; /* XOR plaintext block and computed cipher block */
     }
  }
  return OP_SUCCESS;
} /* End of encrypt_buffer_ofb() */


/** Decrypts the first "len" bytes of buffer "ciphertext" in OFB Mode using the
  * supplied key. The result is stored in buffer "plaintext".
  * @param ciphertext Buffer that contains the data to be decrypted.
  * @param plaintext Buffer where the plaintext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied ciphertext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of ciphertext must be a multiple of the cipher block size.
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::decrypt_buffer_ofb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm){
  unsigned char O_vector[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  int blocksize=0, i=0, j=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len % blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

  /* Iterate through each cipher block */
  for (i=0; i<len; i+=blocksize, plaintext+=blocksize, ciphertext+=blocksize){

     if(i==0){
         /* Set initialization vector */
         if (initial_IV == NULL )
            memset(O_vector, 0, blocksize);
         else
            memcpy(O_vector,initial_IV, blocksize); /* IV was supplied by the caller */
     }

     /* Compute 0_vector_i = Ek( O_vector_i-1 )*/
     switch(algorithm){

            case ALG_BLOWFISH:
                if ( blowfish_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_TWOFISH:
                if ( twofish_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_RIJNDAEL:
                if ( rijndael_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            case ALG_SERPENT:
                if ( serpent_encrypt_buffer(O_vector, O_vector, key, blocksize) != 0)
                    return -1;
            break;

            default:
                 return -3;
            break;
        }

     for (j = 0; j < blocksize; j++){
         plaintext[j] = ciphertext[j] ^ O_vector[j]; /* XOR plaintext block and computed cipher block */
     }
  }
  return OP_SUCCESS;
} /* End of decrypt_buffer_ofb() */


/** Encrypts the first "len" bytes of buffer "plaintext" in ECB Mode using the
  * supplied key. The result is stored in buffer "ciphertext".
  * @param plaintext Buffer that contains the data to be encrypted.
  * @param ciphertext Buffer where the ciphertext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied plaintext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of plaintext must be a multiple of the cipher block size
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::encrypt_buffer_ecb(u8 *ciphertext, u8 *plaintext, u8 *key, int len, int algorithm){
  int blocksize=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

  switch(algorithm){

            case ALG_BLOWFISH:
                if ( blowfish_encrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_TWOFISH:
                if ( twofish_encrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_RIJNDAEL:
                if ( rijndael_encrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_SERPENT:
                if ( serpent_encrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            default:
                 return -3;
            break;
        }
  return OP_SUCCESS;
} /* End of encrypt_buffer_ecb() */


/** Decrypts the first "len" bytes of buffer "ciphertext" in ECB Mode using the
  * supplied key. The result is stored in buffer "plaintext".
  * @param ciphertext Buffer that contains the data to be decrypted.
  * @param plaintext Buffer where the plaintext should be stored.
  * @param inital_IV First initialization vector. If this parameter is NULL then
  *        the initial IV is assumed to be a block of zeroes.
  * @param key Encryption key. It should be 256 bits long.
  * @param len Length of the supplied ciphertext.
  * @param algorithm Cipher to be used. It may be ALG_BLOWFISH, ALG_TWOFISH,
  *        ALG_SERPENT or ALG_RIJNDAEL.
  * @warning Parameter key MUST be at least 32bytes long.
  * @warning Length of ciphertext must be a multiple of the cipher block size.
  *          (8 bytes for Blowfish, 16 bytes for the rest).                   */
int Crypto::decrypt_buffer_ecb(u8 *ciphertext, u8 *plaintext, u8 *key, int len, int algorithm){
  int blocksize=0;

  /* First, get cipher block size*/
  switch(algorithm){
        case ALG_BLOWFISH: blocksize=8; break;
        case ALG_TWOFISH: case ALG_RIJNDAEL: case ALG_SERPENT:  blocksize=16; break;
        default: return OP_FAILURE; break;
  }

  /* Check supplied parameters */
  if(len %blocksize != 0 || len == 0 )
    return OP_FAILURE;
  if (ciphertext == NULL || plaintext == NULL || key == NULL)
    return OP_FAILURE;

  switch(algorithm){

            case ALG_BLOWFISH:
                if ( blowfish_decrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_TWOFISH:
                if ( twofish_decrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_RIJNDAEL:
                if ( rijndael_decrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            case ALG_SERPENT:
                if ( serpent_decrypt_buffer(ciphertext, plaintext, key, len) != 0)
                    return -1;
            break;

            default:
                 return -3;
            break;
        }
  return OP_SUCCESS;
} /* End of decrypt_buffer_ecb() */


int Crypto::encrypt_buffer(u8 *in, size_t inlen, u8 *out, u8 *key, size_t keylen, u8 *iv, int cipher, int mode){
  if(in==NULL || inlen==0 || out==NULL || key==NULL || keylen==0)
    return OP_FAILURE;

  switch(mode){
    case BLOCK_MODE_ECB:
        return encrypt_buffer_ecb(out, in, key, inlen, cipher);
    break;
    case BLOCK_MODE_CBC:
        return encrypt_buffer_cbc(out, in, iv, key, inlen, cipher);
    break;
    case BLOCK_MODE_CFB:
        return encrypt_buffer_cfb(out, in, iv, key, inlen, cipher);
    break;
    case BLOCK_MODE_OFB:
        return encrypt_buffer_ofb(out, in, iv, key, inlen, cipher);
    break;
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of encrypt_buffer() */


int Crypto::decrypt_buffer(u8 *in, size_t inlen, u8 *out, u8 *key, size_t keylen, u8 *iv, int cipher, int mode){
  if(in==NULL || inlen==0 || out==NULL || key==NULL || keylen==0)
    return OP_FAILURE;

  switch(mode){
    case BLOCK_MODE_ECB:
        return decrypt_buffer_ecb(in, out, key, inlen, cipher);
    break;
    case BLOCK_MODE_CBC:
        return decrypt_buffer_cbc(in, out, iv, key, inlen, cipher);
    break;
    case BLOCK_MODE_CFB:
        return decrypt_buffer_cfb(in, out, iv, key, inlen, cipher);
    break;
    case BLOCK_MODE_OFB:
        return decrypt_buffer_ofb(in, out, iv, key, inlen, cipher);
    break;
    default:
        return OP_FAILURE;
    break;
  }
  return OP_SUCCESS;
} /* End of decrypt_buffer() */


/** Derives a key from the supplied passphrase material.
  * @param passphrase must be a NULL-terminated string containing a passphrase
  * (the longer the better)
  * @param result should point to a buffer big enough to hold the requested
  * number of bits.
  * @para bits is the length, in bits, of the desired key. */
#define RFC2898_ITERATIONS 1024
int Crypto::derive_cipher_key(const char *passphrase, u8 *result, int bits){
  /* SALT = HEX: 0xa1d4bab5947f583c8bf8f77cd42cf267
   *        DEC: 215110261169822265005096709055935476327
   * If you want added security, change this magic number to a random 128-bit
   * number.                                                                   */
  u8 salt[16]={0xa1,0xd4,0xba,0x13,0x37,0xde,0xad,0xbe,0xef,0xca,0xfe,0x19,0x73,0x44,0x76,0x77};
  if(passphrase==NULL || result==NULL || bits%8!=0)
     fatal(OUT_2, "%s(): Invalid parameter supplied", __func__);
  PBKDF2::pbkdf2_sha256((u8*)passphrase, strlen(passphrase), salt, 16, bits/8, result, RFC2898_ITERATIONS);
  return OP_SUCCESS;
} /* End of derive_key() */

int Crypto::derive_cipher_key_512(const char *passphrase, u8 *result){
  return derive_cipher_key(passphrase, result, 512);
}

int Crypto::derive_cipher_key_256(const char *passphrase, u8 *result){
  return derive_cipher_key(passphrase, result, 256);
}

int Crypto::derive_cipher_key_128(const char *passphrase, u8 *result){
  return derive_cipher_key(passphrase, result, 128);
}

int Crypto::derive_cipher_key_64(const char *passphrase, u8 *result){
  return derive_cipher_key(passphrase, result, 64);
}


/** Derives a key from the supplied passphrase material.
  * @param passphrase must be a NULL-terminated string containing a passphrase
  * (the longer the better)
  * @param result should point to a buffer big enough to hold the requested
  * number of bits.
  * @para bits is the length, in bits, of the desired key. */
int Crypto::derive_mac_key(const char *passphrase, u8 *result, int bits){
  /* SALT = HEX: 0xa1d4ba0ba0ede553bd9da29307ea2883
   *        DEC: 215110247704882105819699438618558474371
   * If you want added security, change this magic number to a random 128-bit
   * number.                                                                   */
  u8 salt[16]={0xa1,0xd4,0xba,0x0b,0xa0,0xed,0xe5,0x53,0xbd,0x9d,0xa2,0x93,0x07,0xea,0x28,0x83};
  if(passphrase==NULL || result==NULL || bits%8!=0)
     fatal(OUT_2, "%s(): Invalid parameter supplied", __func__);
  PBKDF2::pbkdf2_sha256((u8*)passphrase, strlen(passphrase), salt, 16, bits/8, result, RFC2898_ITERATIONS);
  return OP_SUCCESS;
} /* End of derive_key() */

int Crypto::derive_mac_key_512(const char *passphrase, u8 *result){
  return derive_mac_key(passphrase, result, 512);
}

int Crypto::derive_mac_key_256(const char *passphrase, u8 *result){
  return derive_mac_key(passphrase, result, 256);
}

int Crypto::derive_mac_key_128(const char *passphrase, u8 *result){
  return derive_mac_key(passphrase, result, 128);
}

int Crypto::derive_mac_key_64(const char *passphrase, u8 *result){
  return derive_mac_key(passphrase, result, 64);
}


int Crypto::derive_port_sequence(const char *passphrase, tcp_port_t *dest, size_t total){
  u8 aux_key[SHA256_HASH_LEN];
  u8 hash[SHA256_HASH_LEN];
  u8 pg_salt[16]={0xf3,0x2b,0x20,0x7d,0xec,0x9e,0x08,0xb9,0x0b,0x8f,0x68,0xaf,0x61,0xc5,0xaa,0x4c};
  u8 pl_salt[16]={0x85,0x1b,0xf8,0x31,0x3f,0x9d,0x8f,0x07,0x59,0x4c,0xbd,0xc1,0x6c,0x09,0x3a,0x51};
  u8 aux_buff[SHA256_HASH_LEN*2 + sizeof(pl_salt) + sizeof(u32)];
  u32 i=0;

  if(passphrase==NULL || dest==NULL || total>65535)
      fatal(OUT_2, "%s(%p, %p, %lu): Invalid parameter supplied.", __func__, passphrase, (void *)dest, (unsigned long)total);

  PBKDF2::pbkdf2_sha256((u8*)passphrase, strlen(passphrase), pg_salt, 16, SHA256_HASH_LEN, aux_key, RFC2898_ITERATIONS);
  memset(hash, 0, SHA256_HASH_LEN);

  for(i=0; i<(u32)total; i++){
    do{
        memcpy(aux_buff, hash, SHA256_HASH_LEN);
        memcpy(aux_buff+SHA256_HASH_LEN, aux_key, SHA256_HASH_LEN);
        memcpy(aux_buff+(SHA256_HASH_LEN*2), pl_salt, sizeof(pl_salt));
        memcpy(aux_buff+(SHA256_HASH_LEN*2)+sizeof(pl_salt), &i, sizeof(u32));
        SHA256::sha256sum(aux_buff, sizeof(aux_buff), hash);
        dest[i]=*((tcp_port_t *)hash);
    }while(i!=0 && (dest[i]==0 || isinlist_u16(dest, i, dest[i])) );
  }
  return OP_SUCCESS;
}

