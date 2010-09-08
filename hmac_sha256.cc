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

#include "aldaba.h"
#include "sha256.h"
#include "hmac_sha256.h"
 

void HMAC_SHA256::hmac_sha256_init(hmac_sha256_ctx *ctx, const u8 *key, size_t key_size){
  size_t fill=0;
  size_t num=0;
  size_t i=0;
  const u8 *key_used=NULL;
  u8 key_temp[SHA256_DIGEST_SIZE];

  if (key_size == SHA256_BLOCK_SIZE) {
    key_used = key;
    num = SHA256_BLOCK_SIZE;
  }else{
    if (key_size > SHA256_BLOCK_SIZE) {
        key_used = key_temp;
        num = SHA256_DIGEST_SIZE;
        SHA256::sha256sum(key, key_size, key_temp);
    } else { /* key_size > SHA256_BLOCK_SIZE */
        key_used = key;
        num = key_size;
    }
    fill = SHA256_BLOCK_SIZE - num;

    memset(ctx->block_ipad + num, 0x36, fill);
    memset(ctx->block_opad + num, 0x5c, fill);
  }

  for (i = 0; i < num; i++) {
    ctx->block_ipad[i] = key_used[i] ^ 0x36;
    ctx->block_opad[i] = key_used[i] ^ 0x5c;
  }

  SHA256::sha256_init(&ctx->ctx_inside);
  SHA256::sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);

  SHA256::sha256_init(&ctx->ctx_outside);
  SHA256::sha256_update(&ctx->ctx_outside, ctx->block_opad, SHA256_BLOCK_SIZE);

  /* for hmac_reinit */
  memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof (SHA256_CTX));
  memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,sizeof (SHA256_CTX));
}


void HMAC_SHA256::hmac_sha256_reinit(hmac_sha256_ctx *ctx) {
  memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof (SHA256_CTX));
  memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof (SHA256_CTX));
}


void HMAC_SHA256::hmac_sha256_update(hmac_sha256_ctx *ctx, u8 *message, size_t message_len) {
  SHA256::sha256_update(&ctx->ctx_inside, message, message_len);
}


void HMAC_SHA256::hmac_sha256_final(hmac_sha256_ctx *ctx, u8 *mac, size_t mac_size) {
  u8 digest_inside[SHA256_DIGEST_SIZE];
  u8 mac_temp[SHA256_DIGEST_SIZE];
  SHA256::sha256_final(&ctx->ctx_inside, digest_inside);
  SHA256::sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
  SHA256::sha256_final(&ctx->ctx_outside, mac_temp);
  memcpy(mac, mac_temp, mac_size);
}

void HMAC_SHA256::hmac_sha256(const u8 *key, size_t key_size, u8 *message,
                 size_t message_len, u8 *mac, unsigned mac_size) {
  hmac_sha256_ctx ctx;
  hmac_sha256_init(&ctx, key, key_size);
  hmac_sha256_update(&ctx, message, message_len);
  hmac_sha256_final(&ctx, mac, mac_size);
}
