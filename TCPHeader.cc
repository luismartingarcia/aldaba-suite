
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

#include "TCPHeader.h"
#include "aldaba.h"
#include "tools.h"


TCPHeader::TCPHeader(){
  this->reset();
} /* End of TCPHeader constructor */


TCPHeader::~TCPHeader(){

} /* End of TCPHeader destructor */

/** Sets every attribute to its default value- */
void TCPHeader::reset(){
  memset( &h, 0, TCP_HEADER_LEN + MAX_TCP_OPTIONS_LEN  );
  length=20; /* Initial value 20. This will be incremented if options are used */
  tcpoptlen=0;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * TCPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The TCPHeader class is able to hold a maximum of 60 bytes. If the
  * supplied buffer is longer than that, only the first 60 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 20 bytes (min TCP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int TCPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<TCP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((TCP_HEADER_LEN + MAX_TCP_OPTIONS_LEN), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/** Performs some VERY BASIC checks that intend to validate the information
  * stored in the internal buffer, as a valid protocol header.
  * @warning If the information stored in the object has been set through a
  * call to storeRecvData(), the object's internal length count may be updated
  * if the validation is successful.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int TCPHeader::validate(){
  if(this->getOffset()<5)
    return OP_FAILURE;
  else if(this->getOffset()*4 > this->length)
    return OP_FAILURE;
  this->length=this->getOffset()*4;
  return this->length;
} /* End of validate() */


/** Sets source port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setSrcPort(u16 p){
  h.th_sport = htons(p);
  return OP_SUCCESS;
} /* End of setSrcPort() */


/** Returns source port in HOST byte order */
u16 TCPHeader::getSrcPort(){
  return ntohs(h.th_sport);
} /* End of getSrcPort() */


/** Sets destination port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setDstPort(u16 p){
  h.th_dport = htons(p);
  return OP_SUCCESS;
} /* End of setDstPort() */


/** Returns destination port in HOST byte order  */
u16 TCPHeader::getDstPort(){
  return ntohs(h.th_dport);
} /* End of getDstPort() */


/** Sets sequence number.
 *  @warning Seq number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setSeq(u32 p){
  h.th_seq = htonl(p);
  return OP_SUCCESS;
} /* End of setSeq() */


/** Returns sequence number in HOST byte order */
u32 TCPHeader::getSeq(){
  return ntohl(h.th_seq);
} /* End of getSeq() */


/** Sets acknowledgement number.
 *  @warning ACK number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setAck(u32 p){
  h.th_ack = htonl(p);
  return OP_SUCCESS;
} /* End of setAck() */


/** Returns ACK number in HOST byte order */
u32 TCPHeader::getAck(){
  return ntohl(h.th_ack);
} /* End of getAck() */


/* TODO: Test this method. It may not work becuasse th_off is supposed to
 * be 4 bits long and arg o is 8.
 * UPDATE: It seems to work just fine. However, let's keep this note just
 * in case problems arise. */
int TCPHeader::setOffset(u8 o){
  h.th_off = o;
  return OP_SUCCESS;
} /* End of setOffset() */


int TCPHeader::setOffset(){
  h.th_off = 5 + tcpoptlen/4;
  return OP_SUCCESS;
} /* End of setOffset() */


/** Returns offset value */
u8 TCPHeader::getOffset(){
  return h.th_off;
} /* End of getOffset() */


/** Sets TCP flags */
int TCPHeader::setFlags(u8 f){
  h.th_flags = f;
  return OP_SUCCESS;
} /* End of setFlags() */


/** Returns the 8bit flags field of the TCP header */
u8 TCPHeader::getFlags(){
  return h.th_flags;
} /* End of getFlags() */


/** Sets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::setCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags |= TH_CWR;
  return prev;
} /* End of setCWR() */


/** Unsets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::unsetCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags ^= TH_CWR;
  return prev;
} /* End of unsetCWR() */


/** Get CWR flag */
bool TCPHeader::getCWR(){
  return h.th_flags & TH_CWR;
} /* End of getCWR() */


/** Sets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::setECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECE() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECE() */


/** Get CWR flag */
bool TCPHeader::getECE(){
  return  h.th_flags & TH_ECN;
} /* End of getECE() */


/** Same as setECE() but with a different name since there are two possible
 *  ways to call this flag
 *  @return Previous state of the flag */
bool TCPHeader::setECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECN() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECN() */


/** Get ECN flag */
bool TCPHeader::getECN(){
  return  h.th_flags & TH_ECN;
} /* End of getECN() */


/** Sets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::setURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags |= TH_URG;
  return prev;
} /* End of setURG() */


/** Unsets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::unsetURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags ^= TH_URG;
  return prev;
} /* End of unsetURG() */


/** Get URG flag */
bool TCPHeader::getURG(){
  return  h.th_flags & TH_URG;
} /* End of getURG() */


/** Sets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::setACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags |= TH_ACK;
  return prev;
} /* End of setACK() */


/** Unsets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::unsetACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags ^= TH_ACK;
  return prev;
} /* End of unsetACK() */


/** Get ACK flag */
bool TCPHeader::getACK(){
  return  h.th_flags & TH_ACK;
} /* End of getACK() */


/** Sets flag PUSH
 *  @return Previous state of the flag */
bool TCPHeader::setPUSH(){
  u8 prev = h.th_flags & TH_PUSH;
  h.th_flags |= TH_PUSH;
  return prev;
} /* End of setPUSH() */


/** Unsets flag PUSH
 *  @return Previous state of the flag */
bool TCPHeader::unsetPUSH(){
  u8 prev = h.th_flags & TH_PUSH;
  h.th_flags ^= TH_PUSH;
  return prev;
} /* End of unetPUSH() */


/** Get PUSH flag */
bool TCPHeader::getPUSH(){
  return  h.th_flags & TH_PUSH;
} /* End of getPUSH() */


/** Sets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::setRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags |= TH_RST;
  return prev;
} /* End of setRST() */


/** Unsets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::unsetRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags ^= TH_RST;
  return prev;
} /* End of unsetRST() */


/** Get RST flag */
bool TCPHeader::getRST(){
  return  h.th_flags & TH_RST;
} /* End of getRST() */


/** Sets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::setSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags |= TH_SYN;
  return prev;
} /* End of setSYN() */


/** Unsets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::unsetSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags ^= TH_SYN;
  return prev;
} /* End of unsetSYN() */


/** Get SYN flag */
bool TCPHeader::getSYN(){
  return  h.th_flags & TH_SYN;
} /* End of getSYN() */


/** Sets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::setFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags |= TH_FIN;
  return prev;
} /* End of setFIN() */


/** Unsets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::unsetFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags ^= TH_FIN;
  return prev;
} /* End of unsetFIN() */


/** Get FIN flag */
bool TCPHeader::getFIN(){
  return  h.th_flags & TH_FIN;
} /* End of getFIN() */


/** Sets window size.
 *  @warning Win number must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setWindow(u16 p){
   h.th_win = htons(p);
  return OP_SUCCESS;
} /* End of setWindow() */


/** Returns window size in HOST byte order. */
u16 TCPHeader::getWindow(){
  return ntohs(h.th_win);
} /* End of getWindow() */


/** Sets urgent pointer.
 *  @warning Pointer must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setUrgPointer(u16 l){
  h.th_urp = htons(l);
  return OP_SUCCESS;
} /* End of setUrgPointer() */


/** Returns Urgent Pointer in HOST byte order. */
u16 TCPHeader::getUrgPointer(){
  return ntohs(h.th_urp);
} /* End of getUrgPointer() */

#define MAX_TCP_PAYLOAD_LEN 65495 
int TCPHeader::setSum(struct in_addr src, struct in_addr dst){
  int bufflen;
  u8 aux[ MAX_TCP_PAYLOAD_LEN ];
  /* FROM: RFC 1323: TCP Extensions for High Performance, March 4, 2009
   *
   * "With IP Version 4, the largest amount of TCP data that can be sent in
   *  a single packet is 65495 bytes (64K - 1 - size of fixed IP and TCP
   *  headers)".
   *
   *  In theory TCP should not worry about the practical max payload length
   *  because it is supposed to be independent of the network layer. However,
   *  since TCP does not have any length field and we need to allocate a
   *  buffer, we are using that value. (Note htat in UDPHeader.cc we do just
   *  the opposite, forget about the practical limitation and allow the
   *  theorical limit for the payload.                                       */
  h.th_sum = 0;

  /* Copy packet contents to a buffer */
  bufflen=dumpToBinaryBuffer(aux, MAX_TCP_PAYLOAD_LEN);

  /* Compute checksum */
  h.th_sum = tcp_sum(aux, bufflen, src, dst);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed. */
int TCPHeader::setSum(u16 s){
  h.th_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Returns the TCP checksum field in NETWORK byte order */
u16 TCPHeader::getSum(){
  return h.th_sum;
} /* End of getSum() */
