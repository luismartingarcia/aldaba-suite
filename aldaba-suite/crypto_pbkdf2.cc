
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
#include "crypto_pbkdf2.h"
#include "sha256.h"
#include "hmac_sha256.h"

#define MAX_SALT_LEN 128
int PBKDF2::pbkdf2_sha256(const u8 *passphrase, size_t passphrase_len, u8 *salt, size_t salt_len, size_t desired_key_len, u8 *final_key_buff, u32 nrounds){
  u32 i=0, j=0, cnt=0;
  u8 digest_1[SHA256_HASH_LEN];
  u8 digest_2[SHA256_HASH_LEN];
  u8 aux_salt[MAX_SALT_LEN+4];
  u8 aux_digest[SHA256_HASH_LEN];
  size_t bytes_written=0;

  /* Safe Checks */
  if(passphrase==NULL || salt==NULL || salt_len==0 || salt_len>MAX_SALT_LEN ||
     final_key_buff==NULL || desired_key_len==0 || nrounds==0)
      return OP_FAILURE;
  /* Copy the salt to our aux buffer */
  memcpy(aux_salt, salt, salt_len);
  /* Derive that key! */
  for(cnt=1; desired_key_len>0; cnt++){
    aux_salt[salt_len]   = (cnt >> 24)&0xFF;
    aux_salt[salt_len+1] = (cnt >> 16)&0xFF;
    aux_salt[salt_len+2] = (cnt >> 8)&0xFF;
    aux_salt[salt_len+3] = cnt&0xFF;
    HMAC_SHA256::hmac_sha256(passphrase, passphrase_len, aux_salt, salt_len+4, digest_1, SHA256_HASH_LEN);
    memcpy(aux_digest, digest_1, sizeof(aux_digest));
    for (i = 1; i < nrounds; i++) {
        HMAC_SHA256::hmac_sha256(passphrase, passphrase_len, digest_1, SHA256_HASH_LEN, digest_2, SHA256_HASH_LEN);
        memcpy(digest_1, digest_2, SHA256_HASH_LEN);
	for (j = 0; j < SHA256_HASH_LEN; j++){
            aux_digest[j] ^= digest_1[j];
        }
    }
    bytes_written=MIN(desired_key_len, SHA256_HASH_LEN);
    memcpy(final_key_buff, aux_digest, bytes_written);
    desired_key_len-=bytes_written;
    final_key_buff+=bytes_written;
  };
  return OP_SUCCESS;
} /* End of pbkdf2_sha256() */