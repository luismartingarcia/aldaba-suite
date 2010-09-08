
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

#include "PKAuthAttempt.h"
#include "output.h"

PKAuthAttempt::PKAuthAttempt(size_t chunk_length, u16 seq_ports){
  this->knock_chunk_len=chunk_length;
  this->total_sequence_ports=seq_ports;
  this->knock_data=(u8 *)calloc(this->total_sequence_ports, this->knock_chunk_len);
  this->hits=(u8 *)calloc(this->total_sequence_ports, sizeof(u8));
  if(this->knock_data==NULL || this->hits==NULL){
    fatal(OUT_2, "PKAuthAttempt::PKAuthAttempt(): Not enough memory for new instance.");
  }
  gettimeofday(&this->timestamp, NULL);
  return;
} /* End of PKAuthAttempt constructor */


PKAuthAttempt::~PKAuthAttempt(){
  this->freeMem();
} /* End of PKAuthAttempt destructor */



/** Frees any internal dynamically allocated memory and sets appropriate 
  * pointers to NULL. */
void PKAuthAttempt::freeMem() {
  if(this->knock_data!=NULL){
    free(this->knock_data);
    this->knock_data=NULL;
  }
  if(this->hits!=NULL){
    free(this->hits);
    this->hits=NULL;
  }
} /* End of reset() */



/** Sets every attribute to its default value- */
void PKAuthAttempt::clear() {
  if(this->knock_data!=NULL)
    memset(this->knock_data, 0, this->total_sequence_ports*this->knock_chunk_len);
  if(this->hits!=NULL)
    memset(this->hits, 0, this->total_sequence_ports*sizeof(u8));
  this->clntaddr.reset();
} /* End of reset() */



int PKAuthAttempt::update(u8 *data, tcp_port_t port, tcp_port_t *seq){
  int pos=-1;
  /* Lookup received port position */
  for(u16 i=0; i<this->total_sequence_ports; i++){
      if(port==seq[i]){
          pos=i;
          break;
      }
  }
  if(pos<0){
    return OP_FAILURE;
  }else{
    if(this->hits[pos]==0xFF)
        this->hits[pos]=1;
    else
        this->hits[pos]++;
    memcpy( this->knock_data+(pos*this->knock_chunk_len), data, this->knock_chunk_len );  
  }
  return OP_SUCCESS;
}


bool PKAuthAttempt::complete(){
  for(u16 i=0; i<this->total_sequence_ports; i++){
      if(this->hits[i]==0)
          return false;
  }
  return true;
}


u8 *PKAuthAttempt::getData(){
  return this->getData(NULL);
}


u8 *PKAuthAttempt::getData(size_t *final_len){
  if(final_len!=NULL)
    *final_len=(this->total_sequence_ports*this->knock_chunk_len);
  return this->knock_data;
}


int PKAuthAttempt::setAddress(IPAddress addr){
  this->clntaddr=addr;
  return OP_SUCCESS;
}

IPAddress PKAuthAttempt::getAddress(){
  return this->clntaddr;
}