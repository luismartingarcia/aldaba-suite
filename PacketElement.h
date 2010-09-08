
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

#ifndef PACKETELEMENT_H
#define PACKETELEMENT_H  1

#include "aldaba.h"
#include "output.h"

class PacketElement {

  protected:

    u32 length;
    PacketElement *next;    /**< Next PacketElement (next proto header)      */
    PacketElement *prev;    /**< Prev PacketElement (previous proto header)  */

  public:

    PacketElement();
    ~PacketElement();

    /** This function MUST be overwritten on ANY class that inherits from
      *  this one. Otherwise getBinaryBuffer will fail */
    virtual u8 * getBufferPointer(){
        fatal(OUT_2,"getBufferPointer(): Attempting to use superclass PacketElement method.\n");
        return NULL;
     } /* End of getBufferPointer() */


    /** Returns a buffer that contains the header of the packet + all the
     *  lower level headers and payload. Returned buffer should be ok to be
     *  passes to a send() call to be transferred trough a socket.
     *  @return a pointer to a free()able buffer that contains packet's binary
     *  data.
     *  @warning If there are linked elements, their getBinaryBuffer() method
     *  will be called recursively and the buffers that they return WILL be
     *  free()d as soon as we copy the data in our own allocated buffer.
     *  @warning Calls to this method may not ve very efficient since they
     *  always involved a few malloc()s and free()s. If you want efficiency
     *  use dumpToBinaryBuffer(); */
    virtual u8 * getBinaryBuffer(){
      u8 *ourbuff=NULL;
      u8 *othersbuff=NULL;
      u8 *totalbuff=NULL;
      long otherslen=0;

      /* Get our own buffer address */
      if ( (ourbuff=getBufferPointer()) == NULL ){
          fatal(OUT_2,"getBinaryBuffer(): Couldn't get own data pointer\n");
      }
      if( next != NULL ){ /* There is some other packet element */
        othersbuff = next->getBinaryBuffer();
        otherslen=next->getLen();
        totalbuff=(u8 *)calloc(otherslen + length, 1);
        memcpy(totalbuff, ourbuff, length);
        memcpy(totalbuff+length, othersbuff, otherslen);
        free(othersbuff);
      }else{
           totalbuff=(u8 *)calloc(length, 1);
           memcpy(totalbuff, ourbuff, length);
      }
      return totalbuff;
    } /* End of getBinaryBuffer() */


    virtual int dumpToBinaryBuffer(u8* dst, int maxlen){
      u8 *ourbuff=NULL;
      long ourlength=0;
      /* Get our own buffer address and length */
      if ( (ourbuff=getBufferPointer()) == NULL ||  (ourlength=this->length) < 0 )
            fatal(OUT_2,"getBinaryBuffer(): Couldn't get own data pointer\n");
      /* Copy our part of the buffer */
      if ( maxlen < ourlength )
            fatal(OUT_2,"getBinaryBuffer(): Packet exceeds maximum length %d\n", maxlen);
      memcpy( dst, ourbuff, ourlength);
       /* If there are more elements, tell them to copy their part */
       if( next!= NULL ){
            next->dumpToBinaryBuffer(dst+ourlength, maxlen-ourlength);
       }
       return this->getLen();
    } /* End of dumpToBinaryBuffer() */


    /** Does the same as the previous one but it stores the length of the
     *  return buffer on the memory pointed by the supplied int pointer.     */
    virtual u8 * getBinaryBuffer(int *len){
      u8 *buff = getBinaryBuffer();
      if( len != NULL )
         *len = getLen();
      return buff;
    } /* End of getBinaryBuffer() */


    /** Returns the lenght of this PacketElement + the length of all the
     *  PacketElements that are next to it (are linked trough the "next"
     *  attribute). So for example, if we have IPv4Header p1, linked to
     *  a TCPHeader p2, representing a simple TCP SYN with no options,
     *  a call to p1.getLen() will return 20 (IP header with no options) + 20
     *  (TCP header with no options) = 40 bytes.                             */
    virtual int getLen(){
        /* If we have some other packet element linked, get its length */
        if (next!=NULL)
            return length + next->getLen();
        else
            return length;
    } /* End of getLen() */


    /** Returns the address of the next PacketElement that is linked to this */
    virtual PacketElement *getNextElement(){
      return next;
    } /* End of getNextElement() */


    /** Sets attribute next with the supplied pointer value.
     *  @warning Supplied pointer must point to a PacketElement object or
     *  an object that inherits from it.                                     */
    virtual int setNextElement(PacketElement *n){
      next=n;
      return OP_SUCCESS;
    } /* End of setNextElement() */


    /** Returns the address of the previous PacketElement that is linked to
     *  this one.
     *  @warning In many cases this function will return NULL since there is
     *  a high probability that the user of this class does not link
     *  PacketElements in both directions. Normally one would set attribute
     *  "next" of an IPHeader object to the TCPHeader that follows it, but
     *  not the other way around. */
    virtual PacketElement *getPrevElement(){
      return prev;
    } /* End of getPrevElement() */

};

#endif
