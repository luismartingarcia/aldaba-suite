
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

#include "UDPHeader.h"
#include "aldaba.h"
#include "tools.h"


UDPHeader::UDPHeader(){
  this->reset();
} /* End of UDPHeader constructor */


UDPHeader::~UDPHeader(){

} /* End of UDPHeader destructor */


void UDPHeader::reset(){
  memset(&this->h, 0, UDP_HEADER_LEN);
  this->length=UDP_HEADER_LEN;
  this->h.uh_ulen=htons(UDP_HEADER_LEN); /* Default len 8 bytes (UDP header with no payload) */
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * UDPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The UDPHeader class is able to hold a maximum of 8 bytes. If the
  * supplied buffer is longer than that, only the first 8 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (UDP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int UDPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<UDP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=UDP_HEADER_LEN;
    memcpy(&(this->h), buf, UDP_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */



/** This method is provided for consistency with other classes of the
  * PacketElement family. 99.9% of the cases, it returns 8 (the length of the
  * UDP header). If for somereason, the internal state of the object is not
  * correct, OP_FAILURE (-1) is returned. */
int UDPHeader::validate(){
  if( this->length!=UDP_HEADER_LEN)
      return OP_FAILURE;
  else
      return UDP_HEADER_LEN;
} /* End of validate() */
  
/** Sets source port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int UDPHeader::setSrcPort(u16 p){
  h.uh_sport = htons(p);
  return OP_SUCCESS;
} /* End of setSrcPort() */


/** Returns source port in HOST byte order */
u16 UDPHeader::getSrcPort(){
  return ntohs(h.uh_sport);
} /* End of getSrcPort() */


/** Sets destination port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int UDPHeader::setDstPort(u16 p){
  h.uh_dport = htons(p);
  return OP_SUCCESS;
} /* End of setDstPort() */


/** Returns destination port in HOST byte order */
u16 UDPHeader::getDstPort(){
  return ntohs(h.uh_dport);
} /* End of getDstPort() */


int UDPHeader::setSum(u32 source, u32 destination){
  struct in_addr src;
  struct in_addr dst;
  int bufflen;
  u8 aux[ 65535-8 ];
 /* FROM: RFC 5405 Unicast UDP Usage Guidelines, November 2008
  *  "A UDP datagram is carried in a single IP packet and is hence limited to
  *   a maximum payload of 65,507 bytes for IPv4 and 65,527 bytes for IPv6"
  *
  * So, UDP is supposed to be able to carry 65535-8 bytes but in fact it can
  * only carry 65,507 or 65,527. However, we are not taking that into account
  * here because UDP is supposed to be independent of IPv4, IPv6 or
  * whatever other network layer protocol is used to carry the UDP datagrams.*/
  h.uh_sum = 0;
  src.s_addr=source;
  dst.s_addr=destination;

  /* Copy packet contents to a buffer */
  bufflen=dumpToBinaryBuffer(aux, 65536-8 );

  /* Compute checksum */
  h.uh_sum = tcpudp_cksum(&src, &dst, IPPROTO_UDP, bufflen, (char *) aux);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed. */
int UDPHeader::setSum(u16 s){
  h.uh_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */

u16 UDPHeader::getSum(){
  return h.uh_sum;
} /* End of getSum() */


int UDPHeader::setTotalLength(){
  int mylen = 8;
  int otherslen=0;

  if (next!=NULL)
      otherslen=next->getLen();

 /* FROM: RFC 5405 Unicast UDP Usage Guidelines, November 2008
  *  "A UDP datagram is carried in a single IP packet and is hence limited to
  *   a maximum payload of 65,507 bytes for IPv4 and 65,527 bytes for IPv6"
  *
  * So, UDP is supposed to be able to carry 65535-8 bytes but in fact it can
  * only carry 65,507 or 65,527. However, we are not taking that into account
  * here because UDP is supposed to be independent of IPv4, IPv6 or
  * whatever other network layer protocol is used to carry the UDP datagrams.*/
  if ((mylen+otherslen) > 65535 || (mylen+otherslen)<8 ){
    printf("UDPHeader::setTotalLenght(): Invalid length.\n");
    return OP_FAILURE;
  }

  h.uh_ulen=htons( mylen+otherslen );

  return OP_SUCCESS;
} /* End of setTotalLenght() */


/** @warning Supplied value MUST be in HOST byte order */
int UDPHeader::setTotalLength(u16 l){
  this->h.uh_ulen=htons(l);
  return OP_SUCCESS;
} /* End of setTotalLenght() */


/** @warning Returned value is in HOST byte order */
u16 UDPHeader::getTotalLength(){
  return ntohs(this->h.uh_ulen);
} /* End of getTotalLenght() */
