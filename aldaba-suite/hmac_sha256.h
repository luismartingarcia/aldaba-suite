/*-
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __HMAC_SHA2_H__
#define __HMAC_SHA2_H__ 1

#include "sha256.h"

#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define HMAC_SHA256_LEN (256 / 8)

typedef struct {
    SHA256_CTX ctx_inside;
    SHA256_CTX ctx_outside;

    /* for hmac_reinit */
    SHA256_CTX ctx_inside_reinit;
    SHA256_CTX ctx_outside_reinit;

    u8 block_ipad[SHA256_BLOCK_SIZE];
    u8 block_opad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

class HMAC_SHA256 {

    private:

        static void hmac_sha256_init(hmac_sha256_ctx *ctx, const u8 *key, size_t key_size);
        static void hmac_sha256_reinit(hmac_sha256_ctx *ctx);
        static void hmac_sha256_update(hmac_sha256_ctx *ctx, u8 *message, size_t message_len);
        static void hmac_sha256_final(hmac_sha256_ctx *ctx, u8 *mac, size_t mac_size);

    public:

        static void hmac_sha256(const u8 *key, size_t key_size, u8 *message,
                                size_t message_len, u8 *mac, unsigned mac_size);

}; /* End of class HMAC_SHA256 */

#endif /* __HMAC_SHA2_H__ */

