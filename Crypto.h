
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
#ifndef __CRYPTO_H__
#define __CRYPTO_H__ 1

#include "aldaba.h"

class Crypto {

    public:
        static int test(void);
        static int encrypt_buffer(u8 *in, size_t inlen, u8 *out, u8 *key, size_t keylen, u8 *iv, int cipher, int mode);
        static int decrypt_buffer(u8 *in, size_t inlen, u8 *out, u8 *key, size_t keylen, u8 *iv, int cipher, int mode);
        static int encrypt_buffer_cbc(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int decrypt_buffer_cbc(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int encrypt_buffer_cfb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int decrypt_buffer_cfb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int encrypt_buffer_ofb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int decrypt_buffer_ofb(u8 *ciphertext, u8 *plaintext, u8 *initial_IV, u8 *key, int len, int algorithm);
        static int encrypt_buffer_ecb(u8 *ciphertext, u8 *plaintext, u8 *key, int len, int algorithm);
        static int decrypt_buffer_ecb(u8 *ciphertext, u8 *plaintext, u8 *key, int len, int algorithm);

        static int derive_cipher_key_512(const char *passphrase, u8 *result);
        static int derive_cipher_key_256(const char *passphrase, u8 *result);
        static int derive_cipher_key_128(const char *passphrase, u8 *result);
        static int derive_cipher_key_64(const char *passphrase, u8 *result);

        static int derive_mac_key_512(const char *passphrase, u8 *result);
        static int derive_mac_key_256(const char *passphrase, u8 *result);
        static int derive_mac_key_128(const char *passphrase, u8 *result);
        static int derive_mac_key_64(const char *passphrase, u8 *result);

        static int derive_port_sequence(const char *passphrase, tcp_port_t *dest, size_t total);
        static int get_random_bytes(u8 *dst, int bytes);

    private:

        static int test_serpent(void);
        static int test_twofish(void);
        static int test_rijndael(void);
        static int test_blowfish(void);
        static int test_sha256(void);
        static int test_md5(void);
        static int test_hmacsha256(void);
        static int test_pbkdf2_sha256(void);

        static int derive_cipher_key(const char *passphrase, u8 *result, int bits);
        static int derive_mac_key(const char *passphrase, u8 *result, int bits);

};

#endif /* __CRYPTO_H__ */
