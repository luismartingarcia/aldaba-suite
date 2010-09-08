
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

#include "AuthRecord.h"
#include "aldaba.h"
#include "output.h"
#include <assert.h>

AuthRecord::AuthRecord(u32 time, u8 *nonce, size_t nonce_len){
  assert(nonce!=NULL && nonce_len>0);
  this->timestamp=time;
  memcpy(this->nonce, nonce, MIN(nonce_len, MAX_AUTH_RECORD_NONCE_LEN));
  return;
} /* End of AuthRecord constructor */


AuthRecord::~AuthRecord(){
  this->reset();
} /* End of AuthRecord destructor */


/** Clears stored data */
void AuthRecord::reset() {
  memset(this->nonce, 0, MAX_AUTH_RECORD_NONCE_LEN);
  this->timestamp=0;
} /* End of reset() */


bool AuthRecord::expired(u32 now){
  if(  (now-MAX_CLOCK_SKEW_SECONDS)< this->timestamp && this->timestamp < (now+MAX_CLOCK_SKEW_SECONDS) )
    return false;
  else
    return true;
} /* End of expired() */


/* Determines if the authentication records matches with the supplied values. */
bool AuthRecord::matches(u32 time, u8 *nonce_val, size_t nonce_len){
  if(this->timestamp==time){
    if(!memcmp(this->nonce, nonce_val, MIN(nonce_len, MAX_AUTH_RECORD_NONCE_LEN))){
        return true;
    }
  }
  return false;
} /* End of matches() */


/* Determines if two authentication records are equal. */
bool AuthRecord::operator==(const AuthRecord& other) const {
  if( this->timestamp==other.timestamp ){
    if(!memcmp(this->nonce, other.nonce, MAX_AUTH_RECORD_NONCE_LEN)){
        return true;
    }
  }
  return false;
} /* End of operator== */


u32 AuthRecord::getTimestamp(){
  return this->timestamp;
}

u8 *AuthRecord::getNonce(){
  return this->nonce;
}