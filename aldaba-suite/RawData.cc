
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
 * as this disclaimer does not contain the complete information. Also, note*
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/

#include "RawData.h"
#include "aldaba.h"
#include "output.h"


RawData::RawData(){

  data=NULL;
  length=0;
  data_is_user_supplied=false;

} /* End of RawData contructor */




RawData::RawData(u32 len){

 if(len==0){
    data=NULL;
    length=0;
  }
  else{
    if((data=(u8 *)calloc(len, 1))==NULL)
        fatal(OUT_2, "RawData() Not enough memory.");
    length=len;
    data_is_user_supplied=false;
  }

} /* End of RawData constructor */



/** @warning Supplied pointer can be either a static address or a free()able
 *  memory location. No attempt to free() it will me made by RawData
 *  destructor or any other method,
 */
RawData::RawData(u8 *pnt, u32 len){

  if(len==0 || pnt==NULL){
    data=NULL;
    length=0;
  }
  else{
    data=pnt;
    length=len;
    data_is_user_supplied=true;
  }

} /* End of RawData constructor */



RawData::~RawData(){

  if(data!=NULL && data_is_user_supplied==false){
    free(data);
    data=NULL;
  }

} /* End of RawData destructor */



u8 * RawData::getBufferPointer(){

  return this->data;

} /* End of getBufferPointer() */




int RawData::setBufferPointer(u8 *pnt){

    data=pnt;
    data_is_user_supplied=true;

    return OP_SUCCESS;

} /* End of setBufferPointer() */


int RawData::setBufferPointer(u8 *pnt, u32 len){

    data=pnt;
    length=len;
    data_is_user_supplied=true;

    return OP_SUCCESS;

} /* End of setBufferPointer() */

int RawData::setBufferLen(u32 len){

    length=len;

    return OP_SUCCESS;

} /* End of setBufferPointer() */


/** Copies "len" bytes of data from position "buff" to the object's buffer.
 *  If "len" is more that object's buffer, only the first "length" bytes
 *  are copied. */
int RawData::setBufferContents(u8 *buff, u32 len){

  if( buff==NULL || len<=0 ) /* TODO: Add printf()? */
    return OP_FAILURE;

  int limit = (len < length) ? len : length ;

  for(int i=0; i<limit; i++)
    data[i]=buff[i];

   return OP_SUCCESS;

} /* End of setBufferContents() */




/** @warning This method asuumes that supplied buffer contains at least
 *  length bytes (getDataLen() bytes) */
int RawData::setBufferContents(u8 *buff){

    return setBufferContents(buff, length);

} /* End of setBufferContents() */

