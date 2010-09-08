
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

#include "ICMPv4Header.h"
#include "aldaba.h"
#include "output.h"
#include "tools.h"

ICMPv4Header::ICMPv4Header() {
  this->reset();
} /* End of ICMPv4Header constructor */


ICMPv4Header::~ICMPv4Header() {

} /* End of ICMPv4Header destructor */


void ICMPv4Header::reset(){
  h.type=0; /* TODO: Do we want to set ICMP_ECHO here? Value 0 is ICMP_ECHOREPLY */
  h.code=0;
  h.checksum=0;
  h.h3.f32=0;
  memset (h.data, 0, ICMP_PAYLOAD_LEN );
  routeradventries=0;
} /* End of reset() */


/** Sets every class attribute to zero */
void ICMPv4Header::zero(){
  memset (&h, 0, sizeof(h) );
  routeradventries=0;
} /* End of zero() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv4Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


int ICMPv4Header::setType(u8 val){
  h.type = val;
  length = getICMPHeaderLengthFromType( val );
  return OP_SUCCESS;
} /* End of setType() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getType(){
  return h.type;
} /* End of getType() */


bool ICMPv4Header::validateType(u8 val){
    switch( val ){
        case ICMP_ECHOREPLY:
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
        case ICMP_REDIRECT:
        case ICMP_ECHO:
        case ICMP_ROUTERADVERT:
        case ICMP_ROUTERSOLICIT:
        case ICMP_TIMXCEED:
        case ICMP_PARAMPROB:
        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_TRACEROUTE:
            return true;
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateType() */


bool ICMPv4Header::validateType(){
    return validateType( this->h.type );
} /* End of validateType() */


int ICMPv4Header::setCode(u8 val){
  h.code = val;
  return OP_SUCCESS;
} /* End of setCode() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getCode(){
  return h.code;
} /* End of getCode() */


/** Given an ICMP Type and a code, determines whether the code corresponds to
  * a RCP compliant code (eg: code 0x03  for "port unreachable" in ICMP
  * Unreachable messages) or just some other bogus code. */
bool ICMPv4Header::validateCode(u8 type, u8 code){
    switch (type){
        case ICMP_ECHOREPLY:
            return (code==0);
        break;

        case ICMP_UNREACH:
            switch( code ){
                case ICMP_UNREACH_NET:
                case ICMP_UNREACH_HOST:
                case ICMP_UNREACH_PROTOCOL:
                case ICMP_UNREACH_PORT:
                case ICMP_UNREACH_NEEDFRAG:
                case ICMP_UNREACH_SRCFAIL:
                case ICMP_UNREACH_NET_UNKNOWN:
                case ICMP_UNREACH_HOST_UNKNOWN:
                case ICMP_UNREACH_ISOLATED:
                case ICMP_UNREACH_NET_PROHIB:
                case ICMP_UNREACH_HOST_PROHIB:
                case ICMP_UNREACH_TOSNET:
                case ICMP_UNREACH_TOSHOST:
                case ICMP_UNREACH_COMM_PROHIB:
                case ICMP_UNREACH_HOSTPRECEDENCE:
                case ICMP_UNREACH_PRECCUTOFF:
                    return true;
            }
        break;

        case ICMP_REDIRECT:
            switch( code ){
                case ICMP_REDIRECT_NET:
                case ICMP_REDIRECT_HOST:
                case ICMP_REDIRECT_TOSNET:
                case ICMP_REDIRECT_TOSHOST:
                    return true;
            }
        break;

        case ICMP_ROUTERADVERT:
            switch( code ){
                case 0:
                case ICMP_ROUTERADVERT_MOBILE:
                    return true;
            }
        break;

        case ICMP_TIMXCEED:
            switch( code ){
                case ICMP_TIMXCEED_INTRANS:
                case ICMP_TIMXCEED_REASS:
                    return true;
            }
        break;

        case ICMP_PARAMPROB:
            switch( code ){
                case ICMM_PARAMPROB_POINTER:
                case ICMP_PARAMPROB_OPTABSENT:
                case ICMP_PARAMPROB_BADLEN:
                    return true;
            }
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_ROUTERSOLICIT:
        case ICMP_SOURCEQUENCH:
        case ICMP_ECHO:
            return (code==0);
        break;

        case ICMP_TRACEROUTE:
            switch( code ){
                case ICMP_TRACEROUTE_SUCCESS:
                case ICMP_TRACEROUTE_DROPPED:
                    return true;
            }
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateCode() */


/** Computes the ICMP header checksum and sets the checksum field to the right
 *  value. */
int ICMPv4Header::setSum(){
  u8 buffer[65535];
  int total_len=0;
  h.checksum = 0;
  
  memcpy(buffer, &h, length);
  
  if( this->getNextElement() != NULL)
    total_len=next->dumpToBinaryBuffer(buffer+length, 65535-length);   
  total_len+=length;
  
  h.checksum = in_cksum((unsigned short *)buffer, total_len);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int ICMPv4Header::setSum(u16 s){
  h.checksum = s;
  return OP_SUCCESS;
} /* End of setSum() */



/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 ICMPv4Header::getSum(){
  return h.checksum;
} /* End of getSum() */



/* Dest unreach/Source quench/Time exceeded **********************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setUnused(u32 val){
  h.h3.unused = htonl(val);
  return OP_SUCCESS;
} /* End of setUnused() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getUnused(){
  return ntohl( h.h3.unused );
} /* End of getUnused() */



/* Redirect ******************************************************************/
/** @warning Supplied IP MUST be in NETWORK byte order */
int ICMPv4Header::setPreferredRouter(u32 ipaddr){
  h.h3.addr = ipaddr;
  return OP_SUCCESS;
} /* End of setPreferredRouter() */


/** @warning Returned IP is in NETWORK byte order */
u32 ICMPv4Header::getPreferredRouter(){
  return h.h3.addr;
} /* End of getPreferredRouter() */



/* Parameter problem *********************************************************/

/** Sets pointer value in Parameter Problem messages */
int ICMPv4Header::setPointer(u8 val){
  h.h3.pointer8_unused24[0] = val;
  return OP_SUCCESS;
} /* End of setPointer() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getPointer(){
  return h.h3.pointer8_unused24[0];
} /* End of getPointer() */



/* Router Solicitation *******************************************************/
/* FROM: RFC 1256, ICMP Router Discovery Messages, September 1991

   ICMP Router Solicitation Message

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Reserved                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReserved( u32 val ){
  h.h3.f32= htonl( val );
  return OP_SUCCESS;
} /* End of setReserved() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getReserved(){
  return ntohl( h.h3.f32 );
} /* End of getReserved() */



/* Router Advertisement ******************************************************/
/* FROM: RFC 1256, ICMP Router Discovery Messages, September 1991

  ICMP Router Advertisement Message

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Num Addrs   |Addr Entry Size|           Lifetime            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Router Address[1]                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Preference Level[1]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Router Address[2]                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Preference Level[2]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               .                               |
      |                               .                               |
      |                               .                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

int ICMPv4Header::setNumAddresses(u8 val){
  h.h3.num8_size8_time16[0] = val;
  return OP_SUCCESS;
} /* End of setNumAddresses() */


u8 ICMPv4Header::getNumAddresses(){
  return h.h3.num8_size8_time16[0];
} /* End of getNumAddresses() */


int ICMPv4Header::setAddrEntrySize(u8 val){
  h.h3.num8_size8_time16[1] = val;
  return OP_SUCCESS;
} /* End of setAddrEntrySize() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getAddrEntrySize(){
  return h.h3.num8_size8_time16[1];
} /* End of getAddrEntrySize() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setLifetime(u16 val){
  h.h3.f16[1] = htons(val);
  return OP_SUCCESS;
} /* End of setLifetime() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getLifetime(){
  return ntohs( h.h3.f16[1] );
} /* End of getLifetime() */


/** @warning Asummes entries have a length of 2*32bits and consist of
 *  two 32bit values.
 *  @warning This method automatically updates field "Number of addreses"
 *  calling this->setNumAddresses(). If you want to place a bogus number
 *  on such field, setNumAddresses() must be called AFTER any calls to
 *  addRouterAdvEntry()
 * */
int ICMPv4Header::addRouterAdvEntry( u32 raddr, u32 pref){
  u32 *pnt1=NULL;
  u32 *pnt2=NULL;

  if ( this->routeradventries >= ((ICMP_PAYLOAD_LEN/8) -1) )
    fatal(OUT_2, "addRouterAdEntry(): Not enough space for more entries");

  /* Get pointer */
  pnt1 = (u32 *)(&(h.data[ this->routeradventries*8]));
  pnt2 = (u32 *)(&(h.data[ this->routeradventries*8 + 4]));

  /* Set info */
  *pnt1 = raddr;
  *pnt2 = htonl( pref );

  this->routeradventries++; /* Update entry count */
  length += 8;             /* Update total length of the ICMP packet */
  this->setNumAddresses(  this->routeradventries );
  return OP_SUCCESS;
} /* End of addRouterAdEntry() */


u8 *ICMPv4Header::getRouterAdvEntries(int *num){
  if( this->routeradventries <= 0 )
    return NULL;
  if (num!=NULL)
    *num = this->routeradventries;
  return h.data;
} /* End of getRouterEntries() */


int ICMPv4Header::clearRouterAdvEntries(){
  memset( h.data, 0, ICMP_PAYLOAD_LEN);
  this->routeradventries=0;
  return OP_SUCCESS;
} /* End of clearRouterEntries*/



/* Echo/Timestamp/Mask *******************************************************/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setIdentifier(u16 val){
  h.h3.id_seq[0] = htons(val);
  return OP_SUCCESS;
} /* End of setIdentifier() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getIdentifier(){
  return ntohs( h.h3.id_seq[0] );
} /* End of getIdentifier() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setSequence(u16 val){
  h.h3.id_seq[1]  = htons(val);
  return OP_SUCCESS;
} /* End of setSequence() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getSequence(){
  return ntohs( h.h3.id_seq[1] );
} /* End of getSequence() */



/* Timestamp only ************************************************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setOriginateTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[0]));   /* Point to the first byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setOriginateTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getOriginateTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[0]));   /* Point to the first byte of payload */
  return ntohl( *pnt );
} /* End of getOriginateTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReceiveTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[4]));   /* Point to the 5th byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setReceiveTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getReceiveTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[4]));   /* Point to the 5th byte of payload */
  return ntohl( *pnt );
} /* End of getReceiveTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setTransmitTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[8]));   /* Point to the 9th byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setTransmitTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getTransmitTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[8]));   /* Point to the 9th byte of payload */
  return ntohl( *pnt );
} /* End of getTransmitTimestamp() */



/* Traceroute ****************************************************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setIDNumber(u16 val){
  h.h3.id_unused[0] = htons(val);
  return OP_SUCCESS;
} /* End of setIDNumber() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getIDNumber(){
  return ntohs( h.h3.id_unused[0] );
} /* End of getIDNumber() */



/* Payload *******************************************************************/
int ICMPv4Header::addPayload(const u8 *src, int len){
  if (src == NULL )
    fatal(OUT_2, "addPayload(): NULL pointer supplied.");
  if(len > ICMP_PAYLOAD_LEN || len<0)
    fatal(OUT_2, "addPayload(): Supplied payload is %s.", (len<0) ? "negative" : "too large" );
  memcpy( h.data, src, len );
  length += len; /* Update our total length */
  return OP_SUCCESS;
} /* End of addPayload() */


/** @warning Supplied string MUST be NULL-terminated */
int ICMPv4Header::addPayload(const char *src){
 u8 *pnt = (u8 *)src;
 if(src==NULL)
    return OP_FAILURE;
 addPayload(pnt, strlen(src) );
 return OP_SUCCESS;
} /* End of addPayload() */



/* Miscellanious *************************************************************/

/** Returns the standard ICMP header length for the supplied ICMP message type.
 *  @warning Return value corresponds strictly to the ICMP header, this is,
 *  the minimum length of the ICMP header, variable length payload is never
 *  included. For example, an ICMP Router Advertising has a fixed header of 8
 *  bytes but then the packet contains a variable number of Router Addresses
 *  and Preference Levels, so while the length of that ICMP packet is
 *  8bytes + ValueInFieldNumberOfAddresses*8, we only return 8 because we
 *  cannot guarantee that the NumberOfAddresses field has been set before
 *  the call to this method. Same applies to the rest of types.              */
int ICMPv4Header::getICMPHeaderLengthFromType( u8 type ){

  switch( type ){

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            return 8; /* (+ optional data) */
        break;

        case ICMP_UNREACH:
            return 8; /* (+ payload) */
        break;

        case ICMP_SOURCEQUENCH:
            return 8; /* (+ payload) */
        break;

        case ICMP_REDIRECT:
            return 8; /* (+ payload) */
        break;

        case ICMP_ROUTERADVERT:
            return 8; /* (+ value of NumAddr field * 8 ) */
        break;

        case ICMP_ROUTERSOLICIT:
            return 8;
        break;

        case ICMP_TIMXCEED:
            return 8; /* (+ payload) */
        break;

        case ICMP_PARAMPROB:
            return 8; /* (+ payload) */
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
            return 20;
        break;

        case ICMP_INFO:
        case ICMP_INFOREPLY:
            return 8;
        break;

        case ICMP_MASK:
        case ICMP_MASKREPLY:
            return 12;
        break;

        case ICMP_TRACEROUTE:
            return 20;
        break;

        /* Packets with non RFC-Compliant types will be represented as
           an 8-byte ICMP header, just like the types that don't include
           additional info (time exceeded, router solicitation, etc)  */
        default:
            return 8;
        break;
  }
  return 8;
} /* End of getICMPHeaderLengthFromType() */
