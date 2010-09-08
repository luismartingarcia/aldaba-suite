
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

#include "IPv6Header.h"
#include "aldaba.h"
#include "output.h"


IPv6Header::IPv6Header() {
  this->reset();
} /* End of IPv6Header constructor */


IPv6Header::~IPv6Header() {

} /* End of IPv6Header destructor */


/** Sets every class attribute to zero */
void IPv6Header::reset(){
  memset(&h, 0, sizeof(struct my_ipv6));
  length=40;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *IPv6Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The IPv6Header class is able to hold a maximum of 40 bytes. If the
  * supplied buffer is longer than that, only the first 40 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 40 bytes (IPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int IPv6Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<IPv6_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=IPv6_HEADER_LEN;
    memcpy(&(this->h), buf, IPv6_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/** This method is provided for consistency with other classes of the
  * PacketElement family. 99.9% of the cases, it returns 40 (the length of the
  * IPv6 header). If for some reason, the internal state of the object is not
  * correct, OP_FAILURE (-1) is returned. */
int IPv6Header::validate(){
  if( this->length!=IPv6_HEADER_LEN)
      return OP_FAILURE;
  else
      return IPv6_HEADER_LEN;
} /* End of validate() */


/** Set Version field (4 bits).  */
int IPv6Header::setVersion(u8 val){
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass:4;
        #else
            u8 tclass:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;

  header1stbyte.fullbyte = h.ip6_start[0];
  header1stbyte.halfbyte.ver=val;
  h.ip6_start[0]=header1stbyte.fullbyte;
  return OP_SUCCESS;
} /* End of setVersion() */


/** Set Version field to value 6.  */
int IPv6Header::setVersion(){
  this->setVersion(6);
  return OP_SUCCESS;
} /* End of setVersion() */


/** Returns an 8bit number containing the value of the Version field.  */
u8 IPv6Header::getVersion(){    
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass:4;
        #else
            u8 tclass:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;

  header1stbyte.fullbyte = h.ip6_start[0];  
  return (u8)header1stbyte.halfbyte.ver;  
} /* End of getVersion() */


int IPv6Header::setTrafficClass(u8 val){
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass1:4;
        #else
            u8 tclass1:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  /* Store old contents */
  header1stbyte.fullbyte = h.ip6_start[0];
  header2ndbyte.fullbyte = h.ip6_start[1];

  /* Fill the two 4bit halves */
  header1stbyte.halfbyte.tclass1=val>>4;
  header2ndbyte.halfbyte.tclass2=val;

  /* Write the bytes back to the header */
  h.ip6_start[0]=header1stbyte.fullbyte;
  h.ip6_start[1]=header2ndbyte.fullbyte;
  
  return OP_SUCCESS;
} /* End of setTrafficClass() */


u8 IPv6Header::getTrafficClass(){
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 ver:4;
            u8 tclass1:4;
        #else
            u8 tclass1:4;
            u8 ver:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header1stbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass1:4;
            u8 tclass2:4;
        #else
            u8 tclass2:4;
            u8 tclass1:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }finalbyte;

  header1stbyte.fullbyte = h.ip6_start[0];
  header2ndbyte.fullbyte = h.ip6_start[1];
  finalbyte.halfbyte.tclass1=header1stbyte.halfbyte.tclass1;
  finalbyte.halfbyte.tclass2=header2ndbyte.halfbyte.tclass2;
  return finalbyte.fullbyte;
} /* End of getTrafficClass() */


int IPv6Header::setFlowLabel(u32 val){
  u32 netbyte = htonl(val);
  u8 *pnt=(u8*)&netbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  header2ndbyte.fullbyte = h.ip6_start[1];
  header2ndbyte.halfbyte.flow=pnt[1];
  h.ip6_start[1]=header2ndbyte.fullbyte;
  h.ip6_start[2]=pnt[2];
  h.ip6_start[3]=pnt[3];
  return OP_SUCCESS;
} /* End of setFlowLabel() */


u32 IPv6Header::getFlowLabel(){
  u32 hostbyte=0;
  u8 *pnt=(u8*)&hostbyte;
  union{
    struct firstbyte{
        #if WORDS_BIGENDIAN
            u8 tclass2:4;
            u8 flow:4;
        #else
            u8 flow:4;
            u8 tclass2:4;
        #endif
    }halfbyte;
    u8 fullbyte;
  }header2ndbyte;

  header2ndbyte.fullbyte = h.ip6_start[1];
  pnt[0]=0;
  pnt[1]=header2ndbyte.halfbyte.flow;
  pnt[2]=h.ip6_start[2];
  pnt[3]=h.ip6_start[3];
  hostbyte=ntohl(hostbyte);
  return hostbyte;
} /* End of getFlowLabel() */


int IPv6Header::setPayloadLength(u16 val){
  this->h.ip6_len = htons(val);
  return OP_SUCCESS;
} /* End of setPayloadLength() */


int IPv6Header::setPayloadLength(){
  int otherslen=0;
  if (next!=NULL)
      otherslen=next->getLen();
  setPayloadLength( otherslen );
  return OP_SUCCESS;
} /* End of setTotalLength() */


u16 IPv6Header::getPayloadLength(){
  return ntohs(this->h.ip6_len);
} /* End of getPayloadLength() */


int IPv6Header::setNextHeader(u8 val){
  this->h.ip6_nh = val;
  return OP_SUCCESS;
} /* End of setNextHeader() */


u8 IPv6Header::getNextHeader(){
  return this->h.ip6_nh;
} /* End of getNextHeader() */


/** Sets field "next header" to the number that corresponds to the supplied
 *  protocol name. Currently onyl TCP, UDP and ICMP are supported. Any
 *  help to extend this functionality would be appreciated. For a list of all
 *  proto names and numbers check:
 *  http://www.iana.org/assignments/protocol-numbers/                        */
int IPv6Header::setNextHeader(const char *p){

  if (p==NULL){
    printf("setNextProto(): NULL pointer supplied\n");
    return OP_FAILURE;
  }
  if( !strcasecmp(p, "TCP") )
    setNextHeader(6);   /* 6=IANA number for proto TCP */
  else if( !strcasecmp(p, "UDP") )
    setNextHeader(17);  /* 17=IANA number for proto UDP */
  else if( !strcasecmp(p, "ICMP") )
    setNextHeader(1);   /* 1=IANA number for proto ICMP */
  else
    fatal(OUT_2, "setNextProto(): Invalid protocol number\n");
  return OP_SUCCESS;  
} /* End of setNextHeader() */


int IPv6Header::setHopLimit(u8 val){
  this->h.ip6_hopl = val;
  return OP_SUCCESS;
} /* End of setHopLimit() */


u8 IPv6Header::getHopLimit(){
  return this->h.ip6_hopl;
} /* End of getHopLimit() */


int IPv6Header::setSourceAddress(u8 *val){
  if(val==NULL)
    fatal(OUT_2, "setSourceAddress(): NULL value supplied.");
  memcpy(this->h.ip6_src, val, 16);
  return OP_SUCCESS;
} /* End of setSourceAddress() */


struct in6_addr IPv6Header::getSourceAddress(){
  struct in6_addr ip;
  memset(&ip, 0, sizeof(struct in6_addr));
  memcpy(ip.s6_addr, this->h.ip6_src, 16);
  return ip;
} /* End of getSourceAddress() */


int IPv6Header::setDestinationAddress(u8 *val){
  if(val==NULL)
   fatal(OUT_2, "setDestinationAddress(): NULL value supplied.");
  memcpy(this->h.ip6_dst, val, 16);
  return OP_SUCCESS;
} /* End of setDestinationAddress() */


struct in6_addr IPv6Header::getDestinationAddress(){
  struct in6_addr ip;
  memset(&ip, 0, sizeof(struct in6_addr));
  memcpy(ip.s6_addr, this->h.ip6_dst, 16);
  return ip;
} /* End of getDestinationAddress() */
