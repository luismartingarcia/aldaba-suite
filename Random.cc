
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


int Random::init(){
  // TODO: Finish this!
  srandom((unsigned)time(NULL)); // !!!! Fix me!! todo TODO @todo
  this->init_done=true;
  return OP_SUCCESS;
}


int Random::init(u8 *buff, u32 buff_len){
  memset(buff, 0, buff_len); /* TODO: Change this! */
  return OP_SUCCESS;
}


int Random::getRandomData(void *buff, size_t buff_len){
    u8 *dst=(u8 *)buff;
  /* Make sure we init before we return random data */
  if(!this->init_done)
    this->init();
  for(size_t i=0; i<buff_len; i++) /* TODO: Change this! */
      dst[i]=(u8)rand();
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
