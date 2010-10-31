
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
#include "Random.h"
#include "crypto_pbkdf2.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>


/** Standard constructor. Inits the internal attributes of the object.
  * Basically it just performs a reset() operation. Check Random::reset()
  * documentation for details. */
Random::Random(){
  this->reset();
}

/** Standard destructor. It doesn't free anything (as there is no dinamically
  * allocated data inside the object), but sets the object state to the initial
  * state, through a reset() call. Check Random::reset() documentation for
  * details. */
Random::~Random(){
  this->reset();
}

/** Sets the object to its initial state.  */
void Random::reset(){
  this->init_done=false;
} /* End of reset() */


/** Initializes the internal entropy pool. Basically it uses the current time,
  * the current PID and PPID and a number of nice random bytes obtained from
  * the system's random device. The IV is 128 bytes long. The time, and the two
  * PIDs typically take 24 bytes on a x86_64 machine. That leaves about 104
  * bytes for the random number, this is, 832 bits. Providing the system's
  * random device spits decent enough random numbers, the quality of the numbers
  * generated in Aldaba should be OK for most purposes. */
int Random::init(){
  u8 iv[RND_IV_LEN];
  struct timeval tv;
  pid_t pid;
  size_t count=0;

  /* The seed contains the current time (with microseconds precision), current
   * process id, current parent process id and a random number obtained from
   * the system's random device (tipically /dev/urandom */
  gettimeofday(&tv, NULL);
  memcpy(iv, &tv, sizeof(struct timeval));
  count+=sizeof(struct timeval);

  pid=getpid();
  memcpy(iv+count, &pid, sizeof(pid_t));
  count+=sizeof(pid_t);

  pid=getppid();
  memcpy(iv+count, &pid, sizeof(pid_t));
  count+=sizeof(pid_t);

  get_system_random(iv+count, RND_IV_LEN-count);

  /* From the seed, generate random data until we fill the internal pool */
  PBKDF2::pbkdf2_sha256(iv, RND_IV_LEN, iv+(RND_IV_LEN/2), (RND_IV_LEN/3)+1, POOL_MAX_LEN+RND_IV_LEN, this->pool, PBKDF2_ROUNDS);
  
  /* Some part of the random data needs to be reserved for the next generation */
  memcpy(this->next_iv, this->pool+POOL_MAX_LEN, RND_IV_LEN);

  this->init_done=true;
  this->consumed=0;
  
  return OP_SUCCESS;
} /* End of init() */


/** This function should only be called after the current random number pool
  * has been exhausted. It uses the stored next IV value to refill the pool with
  * more random data */
int Random::reinit(){
  /* Re-generate the pool from the last stored IV */
  PBKDF2::pbkdf2_sha256(this->next_iv, RND_IV_LEN, this->next_iv+1, (RND_IV_LEN/3)+1, POOL_MAX_LEN+RND_IV_LEN, this->pool, PBKDF2_ROUNDS);
  /* Store an IV for next time */
  memcpy(this->next_iv, this->pool+POOL_MAX_LEN, RND_IV_LEN);
  this->consumed=0;
  return OP_SUCCESS;
} /* End of reinit() */


/** Returns a random number of an arbitrary length. The caller can assume that
  * the returned random data is cryptographically secure (at least, this is
  * the best we can reasonably obtain). */
int Random::getRandomData(void *buff, size_t buff_len){
    u8 *dst=(u8 *)buff;

    if(buff==NULL || buff_len==0)
        return OP_FAILURE;

  /* Make sure we init before we return random data */
  if(!this->init_done)
    this->init();

  if( POOL_MAX_LEN-this->consumed >= buff_len){
      memcpy(dst, this->pool+this->consumed, buff_len);
      this->consumed+=buff_len;
      return OP_SUCCESS;
  }else{
    /* Exhaust current buffer */
    u32 left=POOL_MAX_LEN-this->consumed;
    memcpy(dst, this->pool+this->consumed, left);
    this->consumed=POOL_MAX_LEN;
    /* Regerate the pool and obtain the remaining bytes */
    this->reinit();
    getRandomData(dst+left, buff_len-left);
  }
  return OP_SUCCESS;
}

/* @warning no more than 4096 may be requested (NULL will be returned). */
u8 *Random::getRandomData(size_t buff_len){
  static u8 buff[4096];
  if(buff_len<=sizeof(buff)){
    getRandomData(buff, buff_len);
    return buff;
  }else{
    return NULL;
  }
} /* End of getRandomData() */

u32 Random::getRandom32(){
  u32 v;
  getRandomData(&v, sizeof(u32));
  return v;
}

u32 Random::getRandom32NonZero(){
  u32 v;
  while( (v=this->getRandom32())==0 );
  return v;
} /* End of getRandom32NonZero() */


u16 Random::getRandom16(){
  u16 v;
  getRandomData(&v, sizeof(u16));
  return v;
}


u16 Random::getRandom16NonZero(){
  u16 v;
  while( (v=this->getRandom16())==0 );
  return v;
} /* End of getRandom16NonZero() */


u8 Random::getRandom8(){
  u8 v;
  getRandomData(&v, sizeof(u8));
  return v;
}

u8 Random::getRandom8NonZero(){
  u8 v;
  while( (v=this->getRandom8())==0 );
  return v;
} /* End of getRandom8NonZero() */


/** Opens system's PRNG (device /dev/urandom on Linux) and fills the supplied
  * buffer with supposedly nice random data.
  * @return OP_SUCCESS on success.
  * @return less than 0 in case of error.                                     */
int Random::get_system_random(u8 *dst, int bytes){
  int dev_urandom_fd=0;
  int i=0;

  if(dst == NULL || bytes <=0 )
    return OP_FAILURE;

#ifdef WIN32
  HCRYPTPROV hcrypt = 0;
  CryptAcquireContext(&hcrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptGenRandom(hcrypt, bytes, dst);
  CryptReleaseContext(hcrypt, 0);
#else
  /* Open /de/urandom device (or /dev/random)  */
  if( (dev_urandom_fd=open("/dev/urandom", O_RDONLY))<0 ){
    if( (dev_urandom_fd=open("/dev/random", O_RDONLY))<0 ){
      return -1;
    }else{
       /* Set "non-blocking" mode, just in case /dev/random is exhausted */
       set_descriptor_blocking_state(dev_urandom_fd, false);
    }
  }
  /* Get some random data! */
  if ( (i=read(dev_urandom_fd, dst, bytes)) < 0 ){ /* Error */
    close(dev_urandom_fd);
    return -2;
  }else if (i == 0){ /* EOF */
    close(dev_urandom_fd);  
    return -3;
  }else if (i == bytes){ /* Enough data was read   */
    close(dev_urandom_fd); 
    return OP_SUCCESS;
  }else if (i < bytes){ /* Not enough data was read */
    close(dev_urandom_fd);
    return -4;
  }else{
    /* This should never happen */
    printf("#32k8DSF8V: Something is really broken. Please report a bug.\n");
    return -5;
  }
#endif
  return OP_SUCCESS;
} /* End of get_system_random() */